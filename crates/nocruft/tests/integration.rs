// Integration tests for nocruft.
//
// These tests load real BPF programs into the kernel, so they require:
//   - CAP_BPF + CAP_PERFMON (or run as root). Easiest: `sudo -E cargo test`.
//   - Opt-in: NOCRUFT_E2E=1 in the environment, to avoid surprising people
//     who just run `cargo test`.
//
// Tests that don't meet the prerequisites are silently skipped.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn should_run() -> bool {
    if std::env::var("NOCRUFT_E2E").ok().as_deref() != Some("1") {
        return false;
    }
    // BPF loading needs caps. The friendly cap check inside nocruft will
    // bail with a clear message anyway, but skip here to keep `cargo test`
    // output clean.
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        // Could also check capabilities precisely, but root is the common
        // CI/dev setup and avoiding a caps crate keeps deps minimal.
        eprintln!("skipping nocruft e2e tests (not root)");
        return false;
    }
    true
}

// Compose a temp dir name unique per test name. We don't use mkdtemp to
// avoid an extra dep; collisions across runs are handled by always rm -rf
// before use.
fn fresh_tmp(name: &str) -> PathBuf {
    let p = PathBuf::from(format!("/tmp/nocruft-it-{}", name));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

// Run nocruft with the given extra args. The first must be `--nc-exec` etc.
// followed by the child command. Returns captured stdout.
fn run_nocruft(extra: &[&str]) -> String {
    let bin = env!("CARGO_BIN_EXE_nocruft");
    let out = Command::new(bin)
        .args(extra)
        // Inherit stderr so cap/BPF failures land in test output for debug.
        .stderr(std::process::Stdio::inherit())
        .output()
        .expect("spawn nocruft");
    assert!(out.status.success(), "nocruft exited with {:?}", out.status);
    String::from_utf8(out.stdout).expect("stdout utf8")
}

// Extract the lines under "=== created paths (...) ===" up to EOF or blank.
fn parse_summary(out: &str) -> Vec<PathBuf> {
    let mut in_section = false;
    let mut paths = Vec::new();
    for line in out.lines() {
        if line.starts_with("=== created paths") {
            in_section = true;
            continue;
        }
        if in_section {
            if line.is_empty() {
                break;
            }
            paths.push(PathBuf::from(line));
        }
    }
    paths
}

#[test]
fn basic_creation_is_reported() {
    if !should_run() {
        return;
    }
    let dir = fresh_tmp("basic");
    let script = format!("touch {}/a", dir.display());
    let out = run_nocruft(&["--nc-exec", "sh", "--", "-c", &script]);
    let paths = parse_summary(&out);
    assert!(paths.contains(&dir.join("a")), "missing a: {:?}", paths);
}

#[test]
fn deleted_path_omitted_by_default() {
    if !should_run() {
        return;
    }
    let dir = fresh_tmp("deleted");
    let script = format!(
        "touch {0}/tombstone && rm {0}/tombstone && touch {0}/keeper",
        dir.display()
    );
    let out = run_nocruft(&["--nc-exec", "sh", "--", "-c", &script]);
    let paths = parse_summary(&out);
    assert!(paths.contains(&dir.join("keeper")));
    assert!(
        !paths.contains(&dir.join("tombstone")),
        "tombstone should be filtered: {:?}",
        paths
    );
}

#[test]
fn include_deleted_brings_back_tombstone() {
    if !should_run() {
        return;
    }
    let dir = fresh_tmp("deleted-included");
    let script = format!("touch {0}/tombstone && rm {0}/tombstone", dir.display());
    let out = run_nocruft(&[
        "--nc-exec",
        "sh",
        "--nc-include-deleted",
        "--",
        "-c",
        &script,
    ]);
    let paths = parse_summary(&out);
    assert!(
        paths.contains(&dir.join("tombstone")),
        "tombstone should be reported with --nc-include-deleted: {:?}",
        paths
    );
}

#[test]
fn isolation_unrelated_process_not_reported() {
    if !should_run() {
        return;
    }
    let dir = fresh_tmp("isolation");
    let outside = dir.join("OUTSIDE");
    let outside_for_thread = outside.clone();
    // External writer in this test process (not in nocruft's tracked tree).
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        std::fs::File::create(&outside_for_thread).unwrap();
    });
    let script = format!("sleep 0.4; touch {}/inside", dir.display());
    let out = run_nocruft(&["--nc-exec", "sh", "--", "-c", &script]);
    writer.join().unwrap();
    let paths = parse_summary(&out);
    assert!(paths.contains(&dir.join("inside")), "missing inside");
    assert!(
        !paths.contains(&outside),
        "OUTSIDE file should not be reported (created by untracked process): {:?}",
        paths
    );
}

#[test]
fn nested_child_creation_tracked() {
    if !should_run() {
        return;
    }
    let dir = fresh_tmp("nested");
    // sh -> sh -> touch. Three process levels deep.
    let script = format!("sh -c 'sh -c \"touch {}/nested\"'", dir.display());
    let out = run_nocruft(&["--nc-exec", "sh", "--", "-c", &script]);
    let paths = parse_summary(&out);
    assert!(
        paths.contains(&dir.join("nested")),
        "nested creation missing: {:?}",
        paths
    );
}

#[test]
fn cwd_relative_resolution_through_mkdir_p() {
    if !should_run() {
        return;
    }
    let dir = fresh_tmp("mkdirp");
    let script = format!("cd {} && mkdir -p deep/nest/three", dir.display());
    let out = run_nocruft(&["--nc-exec", "sh", "--", "-c", &script]);
    let paths = parse_summary(&out);
    for child in &["deep", "deep/nest", "deep/nest/three"] {
        let full = dir.join(child);
        assert!(
            paths.contains(&full),
            "{} missing: {:?}",
            full.display(),
            paths
        );
    }
}

#[test]
fn modified_existing_file_filtered_by_btime() {
    if !should_run() {
        return;
    }
    let dir = fresh_tmp("modified");
    let pre = dir.join("preexisting.txt");
    std::fs::write(&pre, "hello").unwrap();
    // Ensure the file's btime is strictly before nocruft's start_unix_ns.
    // Most filesystems have ns-resolution btime, but be defensive.
    std::thread::sleep(Duration::from_millis(1500));

    let script = format!("touch {}", pre.display()); // O_CREAT but already exists
    let out = run_nocruft(&["--nc-exec", "sh", "--", "-c", &script]);
    let paths = parse_summary(&out);
    assert!(
        !paths.contains(&pre),
        "pre-existing file (modified, not created) should be filtered: {:?}",
        paths
    );

    // Sanity: same scenario with --nc-include-modified brings it back.
    let out2 = run_nocruft(&[
        "--nc-exec",
        "sh",
        "--nc-include-modified",
        "--",
        "-c",
        &script,
    ]);
    let paths2 = parse_summary(&out2);
    assert!(
        paths2.contains(&pre),
        "--nc-include-modified should re-surface modified file: {:?}",
        paths2
    );
}

#[test]
fn build_artifact_filter_default_and_opt_in() {
    if !should_run() {
        return;
    }
    // Default run: junk under node_modules hidden, sibling file kept.
    let dir = fresh_tmp("build-artifact");
    let script = format!(
        "mkdir -p {0}/node_modules && touch {0}/node_modules/junk && touch {0}/real",
        dir.display()
    );
    let out = run_nocruft(&["--nc-exec", "sh", "--", "-c", &script]);
    let paths = parse_summary(&out);
    assert!(paths.contains(&dir.join("real")));
    assert!(
        !paths.contains(&dir.join("node_modules/junk")),
        "node_modules entry should be filtered: {:?}",
        paths
    );

    // Opt back in. Re-fresh the dir so btime is "after" the second run's
    // start; otherwise the modified-vs-created filter would also drop the
    // entries and obscure what we're testing.
    let dir = fresh_tmp("build-artifact");
    let script = format!(
        "mkdir -p {0}/node_modules && touch {0}/node_modules/junk && touch {0}/real",
        dir.display()
    );
    let out2 = run_nocruft(&["--nc-exec", "sh", "--nc-include-build", "--", "-c", &script]);
    let paths2 = parse_summary(&out2);
    assert!(
        paths2.contains(&dir.join("node_modules/junk")),
        "--nc-include-build should re-surface artifacts: {:?}",
        paths2
    );
}

#[test]
fn user_exclude_glob_drops_matches() {
    if !should_run() {
        return;
    }
    let dir = fresh_tmp("exclude-glob");
    let pattern = format!("{}/**/*.log", dir.display());
    let script = format!("touch {0}/keep.txt {0}/skip.log", dir.display());
    let out = run_nocruft(&[
        "--nc-exec",
        "sh",
        "--nc-exclude",
        &pattern,
        "--",
        "-c",
        &script,
    ]);
    let paths = parse_summary(&out);
    assert!(paths.contains(&dir.join("keep.txt")));
    assert!(
        !paths.contains(&dir.join("skip.log")),
        "--nc-exclude pattern should drop matching paths: {:?}",
        paths
    );
}
