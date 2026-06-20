// Output formatting + post-processing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::bpf_events::{syscall_name, EV_OPENAT_CREATE};
use crate::cli::{NocruftFlags, PatternSet};
use crate::pathres::{exists_now, file_btime_unix_ns, resolve, CapturedEvent};

// Prefixes considered "system noise" and filtered out by default.
const SYSTEM_PREFIXES: &[&str] = &[
    "/dev/",
    "/proc/",
    "/sys/",
    "/run/",
    "/var/run/",
    "/tmp/.X11-unix/",
    "/tmp/.ICE-unix/",
];

fn is_system_path(p: &Path) -> bool {
    let s = match p.to_str() {
        Some(s) => s,
        None => return false,
    };
    SYSTEM_PREFIXES.iter().any(|pfx| s.starts_with(pfx))
}

// Well-known history files that shells and REPLs rotate via atomic write+
// rename. Excluded by default because their fresh inode birth-time defeats
// the modified-vs-created heuristic.
const HISTORY_BASENAMES: &[&str] = &[
    ".bash_history",
    ".zsh_history",
    ".zhistory",
    ".python_history",
    ".node_repl_history",
    ".mysql_history",
    ".psql_history",
    ".rediscli_history",
    ".sqlite_history",
    ".lesshst",
    ".viminfo",
    ".lua_history",
    ".gdb_history",
];

fn is_history_file(p: &Path) -> bool {
    p.file_name()
        .and_then(|s| s.to_str())
        .map(|n| HISTORY_BASENAMES.contains(&n))
        .unwrap_or(false)
}

const BUILD_DIR_COMPONENTS: &[&str] = &[
    ".git",
    "node_modules",
    "__pycache__",
    ".next",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
];

const BUILD_FILE_EXTENSIONS: &[&str] = &["pyc", "pyo"];

fn is_build_artifact(p: &Path) -> bool {
    for comp in p.components() {
        if let std::path::Component::Normal(s) = comp {
            if let Some(s) = s.to_str() {
                if BUILD_DIR_COMPONENTS.contains(&s) {
                    return true;
                }
            }
        }
    }
    if let Some(s) = p.to_str() {
        if s.contains("/target/debug/")
            || s.contains("/target/release/")
            || s.contains("/target/wasm32-")
            || s.contains("/target/aarch64-")
            || s.contains("/target/x86_64-")
        {
            return true;
        }
    }
    if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
        if BUILD_FILE_EXTENSIONS.contains(&ext) {
            return true;
        }
    }
    false
}

// For an EV_OPENAT_CREATE event, decide whether the file existed before
// nocruft started.
fn is_genuine_creation(ev: &CapturedEvent, path: &Path, start_unix_ns: u64) -> bool {
    if ev.syscall != EV_OPENAT_CREATE {
        return true;
    }
    match file_btime_unix_ns(path) {
        Some(btime) => btime >= start_unix_ns,
        None => true,
    }
}

// Combined per-event filter. Returns Some(path) if the event passes all
// active filters, None otherwise. Centralizes the filter logic so all
// output modes apply identical rules.
//
// Order of operations:
//   1. existence (drop missing unless --nc-include-deleted)
//   2. user --nc-include: force keep, skipping all category filters below
//   3. user --nc-exclude: force drop
//   4. category filters (system/modified/history/build) per their flags
fn filter_event(
    ev: &CapturedEvent,
    flags: &NocruftFlags,
    start_unix_ns: u64,
    patterns: &PatternSet,
) -> Option<PathBuf> {
    // BPF-side path buffer is 256 bytes; anything longer is flagged
    // truncated and the resolved path would be wrong. Drop these from
    // the user-facing output; --nc-verbose debug logs already note them.
    if ev.truncated {
        return None;
    }
    let abs = resolve(ev)?;
    if !flags.include_deleted && !exists_now(&abs) {
        return None;
    }
    let abs_str = abs.to_str().unwrap_or("");
    if patterns.includes.iter().any(|p| p.matches(abs_str)) {
        return Some(abs);
    }
    if patterns.excludes.iter().any(|p| p.matches(abs_str)) {
        return None;
    }
    if !flags.include_system && is_system_path(&abs) {
        return None;
    }
    if !flags.include_modified && !is_genuine_creation(ev, &abs, start_unix_ns) {
        return None;
    }
    if !flags.include_history && is_history_file(&abs) {
        return None;
    }
    if !flags.include_build && is_build_artifact(&abs) {
        return None;
    }
    Some(abs)
}

#[derive(Debug, Serialize)]
struct JsonRecord<'a> {
    ts_ns: u64,
    pid: u32,
    syscall: &'a str,
    dirfd: i32,
    flags: u32,
    truncated: bool,
    raw_path: &'a str,
    resolved: String,
    exists: bool,
}

// Top-level entry from main.rs.
pub fn emit(
    events: &[CapturedEvent],
    flags: &NocruftFlags,
    start_unix_ns: u64,
    patterns: &PatternSet,
) {
    if flags.json {
        emit_json(events, flags, start_unix_ns, patterns);
        warn_delete_incompatible(flags, "--nc-json");
        return;
    }

    if flags.no_dedupe {
        emit_plain_no_dedupe(events, flags, start_unix_ns, patterns);
        warn_delete_incompatible(flags, "--nc-no-dedupe");
        return;
    }

    let summary = build_summary(events, flags, start_unix_ns, patterns);
    emit_plain(&summary, flags);

    // Dangerous wins if both are set (it's the more explicit choice).
    if flags.delete_dangerous {
        if let Err(e) = dangerous_delete(&summary) {
            eprintln!("nocruft: delete failed: {}", e);
        }
    } else if flags.delete_interactive {
        if let Err(e) = interactive_delete(&summary) {
            eprintln!("nocruft: interactive delete failed: {}", e);
        }
    }
}

fn warn_delete_incompatible(flags: &NocruftFlags, mode: &str) {
    if flags.delete_interactive {
        eprintln!("nocruft: --nc-delete-interactive ignored with {}", mode);
    }
    if flags.delete_dangerous {
        eprintln!("nocruft: --nc-delete-dangerous ignored with {}", mode);
    }
}

fn build_summary(
    events: &[CapturedEvent],
    flags: &NocruftFlags,
    start_unix_ns: u64,
    patterns: &PatternSet,
) -> Vec<PathBuf> {
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();
    for ev in events {
        if let Some(abs) = filter_event(ev, flags, start_unix_ns, patterns) {
            seen.insert(abs);
        }
    }
    seen.into_iter().collect()
}

fn emit_plain(summary: &[PathBuf], flags: &NocruftFlags) {
    println!();
    println!("=== created paths ({}) ===", summary.len());
    let prefix = if flags.dry_run_delete {
        "would delete: "
    } else {
        ""
    };
    for p in summary {
        println!("{}{}", prefix, p.display());
    }
}

fn emit_plain_no_dedupe(
    events: &[CapturedEvent],
    flags: &NocruftFlags,
    start_unix_ns: u64,
    patterns: &PatternSet,
) {
    println!();
    println!("=== events ({}) ===", events.len());
    let prefix = if flags.dry_run_delete {
        "would delete: "
    } else {
        ""
    };
    for ev in events {
        let Some(abs) = filter_event(ev, flags, start_unix_ns, patterns) else {
            continue;
        };
        println!(
            "{}[{}] pid={} {}",
            prefix,
            syscall_name(ev.syscall),
            ev.pid,
            abs.display()
        );
    }
}

fn emit_json(
    events: &[CapturedEvent],
    flags: &NocruftFlags,
    start_unix_ns: u64,
    patterns: &PatternSet,
) {
    use std::io::Write;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();

    for ev in events {
        let Some(abs) = filter_event(ev, flags, start_unix_ns, patterns) else {
            continue;
        };
        if !flags.no_dedupe && !seen.insert(abs.clone()) {
            continue;
        }
        let rec = JsonRecord {
            ts_ns: ev.ts_ns,
            pid: ev.pid,
            syscall: syscall_name(ev.syscall),
            dirfd: ev.dirfd,
            flags: ev.flags,
            truncated: ev.truncated,
            raw_path: &ev.raw_path,
            resolved: abs.display().to_string(),
            exists: exists_now(&abs),
        };
        let _ = writeln!(out, "{}", serde_json::to_string(&rec).unwrap());
    }
}

// Interactive cleanup. inquire's MultiSelect natively supports
// Right-arrow = select all, Left-arrow = deselect all, Space = toggle,
// and renders the keymap below the prompt.
fn interactive_delete(paths: &[PathBuf]) -> anyhow::Result<()> {
    use std::io::IsTerminal;

    if paths.is_empty() {
        println!();
        println!("(nothing to delete)");
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        eprintln!("nocruft: --nc-delete-interactive requires an interactive terminal");
        return Ok(());
    }

    let items: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();

    println!();
    let selected: Vec<String> = match inquire::MultiSelect::new("Select paths to DELETE:", items)
        .with_page_size(20)
        .with_help_message(
            "space=toggle, →=all, ←=none, type=filter, enter=confirm, esc=abort",
        )
        .prompt()
    {
        Ok(v) => v,
        Err(inquire::InquireError::OperationCanceled)
        | Err(inquire::InquireError::OperationInterrupted) => {
            println!("aborted, nothing deleted");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    if selected.is_empty() {
        println!("no paths selected");
        return Ok(());
    }

    // Single-keypress y/N: no Enter needed. Anything that isn't y/Y aborts.
    if !confirm_single_key(&format!("Delete {} path(s)?", selected.len())) {
        println!("aborted, nothing deleted");
        return Ok(());
    }

    // selected gives us the chosen display strings; map back to PathBuf.
    let selected_paths: Vec<PathBuf> = selected.into_iter().map(PathBuf::from).collect();
    let targets: Vec<&PathBuf> = selected_paths.iter().collect();
    let (ok, fail) = perform_delete(&targets);
    println!("done: {} deleted, {} failed", ok, fail);
    Ok(())
}

// Non-interactive bulk delete. No prompt, no confirmation, no selection.
// Used by --nc-delete-dangerous.
fn dangerous_delete(paths: &[PathBuf]) -> anyhow::Result<()> {
    if paths.is_empty() {
        println!();
        println!("(nothing to delete)");
        return Ok(());
    }
    println!();
    println!(
        "--nc-delete-dangerous: deleting {} path(s) without confirmation",
        paths.len()
    );
    let targets: Vec<&PathBuf> = paths.iter().collect();
    let (ok, fail) = perform_delete(&targets);
    println!("done: {} deleted, {} failed", ok, fail);
    Ok(())
}

// Shared delete worker. Deepest paths first so children get removed before
// parents; remove_dir then succeeds on dirs whose only contents nocruft
// itself reported. If a dir has unrelated contents we did not see, its
// removal fails with ENOTEMPTY rather than nuking unknown data.
fn perform_delete(targets_in: &[&PathBuf]) -> (usize, usize) {
    let mut targets: Vec<&PathBuf> = targets_in.to_vec();
    targets.sort_by_key(|p| std::cmp::Reverse(p.components().count()));

    let mut ok = 0usize;
    let mut fail = 0usize;
    for p in targets {
        let meta = match std::fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(_) => {
                eprintln!("skip (gone): {}", p.display());
                continue;
            }
        };
        let res = if meta.is_dir() && !meta.file_type().is_symlink() {
            std::fs::remove_dir(p)
        } else {
            std::fs::remove_file(p)
        };
        match res {
            Ok(_) => {
                println!("deleted: {}", p.display());
                ok += 1;
            }
            Err(e) => {
                eprintln!("failed: {}: {}", p.display(), e);
                fail += 1;
            }
        }
    }
    (ok, fail)
}

// Single-keypress y/n prompt. Avoids the "type y, then Enter" two-stroke
// dance of inquire::Confirm. y/Y returns true; anything else (including
// n/N, Esc, Enter, Ctrl-C) returns false. Raw mode is restored on exit
// even if the read errors.
fn confirm_single_key(prompt: &str) -> bool {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use crossterm::terminal;
    use std::io::Write;

    print!("{} (y/N) ", prompt);
    let _ = std::io::stdout().flush();

    if terminal::enable_raw_mode().is_err() {
        // Couldn't switch to raw mode; fall back to line-buffered read so
        // we don't lose the prompt entirely.
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        return matches!(line.trim(), "y" | "Y" | "yes");
    }

    let yes = loop {
        let Ok(ev) = event::read() else { break false };
        let Event::Key(k) = ev else { continue };
        // Only react to key-press events (avoid double-firing on key-release
        // on terminals that emit both).
        if k.kind != KeyEventKind::Press && k.kind != KeyEventKind::Repeat {
            continue;
        }
        // Ctrl-C aborts.
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            break false;
        }
        match k.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => break true,
            KeyCode::Char('n')
            | KeyCode::Char('N')
            | KeyCode::Esc
            | KeyCode::Enter => break false,
            _ => continue,
        }
    };

    let _ = terminal::disable_raw_mode();
    println!("{}", if yes { "y" } else { "n" });
    yes
}
