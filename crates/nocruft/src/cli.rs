// CLI parsing for nocruft.
//
// We do NOT use clap to parse the whole argv. Most flags belong to nix-shell
// (-p, --pure, --run, shell.nix, etc.) and clap would refuse to recognize them.
//
// Strategy:
//   1. Walk argv. Tokens starting with `--nc-` are routed to the nocruft
//      bucket. Known nc value-flags consume the next token too.
//   2. Everything else (including bare `--`, `-p`, file names) goes verbatim
//      to the nix-shell bucket.
//   3. clap parses the nocruft bucket into a typed struct.

use anyhow::{bail, Result};
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "nocruft",
    about = "Trace filesystem creations under a nix-shell via eBPF",
    long_about = None,
    no_binary_name = true,
    version,
)]
pub struct NocruftFlags {
    /// Emit one JSON object per line per event instead of the plain summary.
    #[arg(long = "nc-json")]
    pub json: bool,

    /// Keep paths that no longer exist on the filesystem.
    #[arg(long = "nc-include-deleted")]
    pub include_deleted: bool,

    /// Do not deduplicate; print one entry per captured event.
    #[arg(long = "nc-no-dedupe")]
    pub no_dedupe: bool,

    /// Verbose (debug-level) logging on stderr.
    #[arg(long = "nc-verbose")]
    pub verbose: bool,

    /// Show what would be deleted (prefix lines with "would delete: ").
    #[arg(long = "nc-dry-run-delete")]
    pub dry_run_delete: bool,

    /// Interactively select created paths for deletion. The prompt
    /// supports Space (toggle), Right (select all), Left (deselect all),
    /// Enter (confirm), Esc/Ctrl-C (abort).
    #[arg(long = "nc-delete-interactive")]
    pub delete_interactive: bool,

    /// DELETE EVERY REPORTED PATH WITHOUT ASKING after the program exits.
    /// No multi-select, no confirmation. Use with care. Combine with
    /// `--nc-dry-run-delete` first to preview.
    #[arg(long = "nc-delete-dangerous")]
    pub delete_dangerous: bool,

    /// Do not filter out system pseudo-fs paths (/dev, /proc, /sys, /run, ...).
    #[arg(long = "nc-include-system")]
    pub include_system: bool,

    /// Include O_CREAT opens of files that already existed (i.e. modified,
    /// not created). Disabled by default since shells/editors touch
    /// histfiles/configs constantly without creating them.
    #[arg(long = "nc-include-modified")]
    pub include_modified: bool,

    /// Include well-known shell/repl history files
    /// (.bash_history, .zsh_history, .python_history, etc.) that shells
    /// frequently rotate via atomic write-then-rename, which defeats the
    /// btime-based "modified vs created" heuristic.
    #[arg(long = "nc-include-history")]
    pub include_history: bool,

    /// Include paths under common build-artifact directories
    /// (.git, node_modules, __pycache__, cargo target/, .next, *.pyc).
    /// Disabled by default since these dominate the output and are
    /// well understood as machine-generated.
    #[arg(long = "nc-include-build")]
    pub include_build: bool,

    /// Glob pattern matching absolute paths to drop from the output
    /// (repeatable). Use `**` to match across slashes, e.g.
    /// `--nc-exclude '/home/me/.cache/**'` or `--nc-exclude '**/*.log'`.
    #[arg(long = "nc-exclude", value_name = "GLOB")]
    pub exclude: Vec<String>,

    /// Glob pattern matching absolute paths to FORCE-INCLUDE, overriding
    /// built-in and user exclusions (repeatable). Useful to re-surface
    /// something a default filter would drop.
    #[arg(long = "nc-include", value_name = "GLOB")]
    pub include: Vec<String>,

    /// Debug aid: run this binary instead of `nix-shell`. Mainly for tests.
    #[arg(long = "nc-exec", value_name = "PROG")]
    pub exec: Option<String>,
}

pub struct Parsed {
    pub flags: NocruftFlags,
    /// Argv for the child process (excluding argv[0]).
    pub child_args: Vec<String>,
    /// argv[0] for the child process.
    pub child_prog: String,
    /// Pre-compiled --nc-exclude / --nc-include glob patterns.
    pub patterns: PatternSet,
}

#[derive(Debug, Default)]
pub struct PatternSet {
    pub includes: Vec<glob::Pattern>,
    pub excludes: Vec<glob::Pattern>,
}

impl PatternSet {
    pub fn compile(flags: &NocruftFlags) -> anyhow::Result<Self> {
        let includes = compile_each(&flags.include, "--nc-include")?;
        let excludes = compile_each(&flags.exclude, "--nc-exclude")?;
        Ok(Self { includes, excludes })
    }
}

fn compile_each(patterns: &[String], label: &str) -> anyhow::Result<Vec<glob::Pattern>> {
    let mut out = Vec::with_capacity(patterns.len());
    for p in patterns {
        out.push(
            glob::Pattern::new(p)
                .map_err(|e| anyhow::anyhow!("invalid {} pattern {:?}: {}", label, p, e))?,
        );
    }
    Ok(out)
}

// Long flags that take an OWN_TOKEN-style value, e.g. `--nc-exec foo`. The
// `--nc-foo=value` form (single token) is handled separately and does not
// need to be listed here.
const VALUE_FLAGS: &[&str] = &["--nc-exec", "--nc-exclude", "--nc-include"];

// nocruft's own meta flags that don't carry the --nc- prefix. Routed to
// clap so `nocruft --help` and `nocruft --version` work as users expect.
// To pass `--help` to nix-shell, use a `--` separator: `nocruft -- --help`.
const BARE_NC_FLAGS: &[&str] = &["--help", "-h", "--version", "-V"];

pub fn parse_argv(argv: impl IntoIterator<Item = String>) -> Result<Parsed> {
    let mut nc_bucket: Vec<String> = Vec::new();
    let mut child_bucket: Vec<String> = Vec::new();

    // After we see a literal `--`, everything is verbatim child argv with
    // no further --nc-* interpretation. This lets users override the
    // routing of e.g. `--help` to send it to nix-shell instead.
    let mut after_separator = false;

    let mut iter = argv.into_iter();
    while let Some(tok) = iter.next() {
        if after_separator {
            child_bucket.push(tok);
            continue;
        }
        if tok == "--" {
            after_separator = true;
            continue;
        }
        if BARE_NC_FLAGS.contains(&tok.as_str()) {
            nc_bucket.push(tok);
            continue;
        }
        if let Some(rest) = tok.strip_prefix("--nc-") {
            nc_bucket.push(tok.clone());

            let key = if let Some(eq) = rest.find('=') {
                format!("--nc-{}", &rest[..eq])
            } else {
                tok.clone()
            };
            if !rest.contains('=') && VALUE_FLAGS.contains(&key.as_str()) {
                let Some(val) = iter.next() else {
                    bail!("flag {} requires a value", key);
                };
                nc_bucket.push(val);
            }
        } else {
            child_bucket.push(tok);
        }
    }

    let flags = NocruftFlags::try_parse_from(nc_bucket)?;
    let patterns = PatternSet::compile(&flags)?;

    let child_prog = flags
        .exec
        .clone()
        .unwrap_or_else(|| "nix-shell".to_string());

    Ok(Parsed {
        flags,
        child_args: child_bucket,
        child_prog,
        patterns,
    })
}
