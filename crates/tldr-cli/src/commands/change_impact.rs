//! Change Impact command - Find tests affected by code changes
//!
//! Wires tldr-core::change_impact to the CLI (Session 6 Phases 1-5).
//!
//! # Detection Methods
//! - `--files` - Explicit file list
//! - `--base <branch>` - Git diff against base branch (for PRs)
//! - `--staged` - Only staged files
//! - `--uncommitted` - Staged + unstaged (default git mode)
//! - Default: git diff HEAD
//!
//! # Output Formats
//! - JSON (default): Full report structure
//! - Text: Human-readable summary
//! - Runner formats: pytest, pytest-k, jest, go-test, cargo-test

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

use tldr_core::{
    change_impact_extended, ChangeImpactReport, ChangeImpactStatus, DetectionMethod, Language,
};

use crate::output::{format_change_impact_text, OutputFormat, OutputWriter};
use crate::path_validation::require_directory;

/// Find tests affected by code changes
#[derive(Debug, Args)]
pub struct ChangeImpactArgs {
    /// Project root directory (default: current directory)
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Programming language (auto-detect if not specified)
    #[arg(long, short = 'l')]
    pub lang: Option<Language>,

    // === Change Detection ===
    /// Explicit list of changed files (comma-separated)
    #[arg(long, short = 'F', value_delimiter = ',')]
    pub files: Vec<PathBuf>,

    /// Git base branch for diff (e.g., "origin/main" for PR workflow)
    #[arg(long, short = 'b')]
    pub base: Option<String>,

    /// Use git diff to find changed files (default base: HEAD~1, Python parity)
    #[arg(long)]
    pub git: bool,

    /// Git ref to diff against when using --git (default: HEAD~1)
    #[arg(long)]
    pub git_base: Option<String>,

    /// Only consider staged files (pre-commit workflow)
    #[arg(long)]
    pub staged: bool,

    /// Consider all uncommitted changes (staged + unstaged)
    #[arg(long)]
    pub uncommitted: bool,

    /// Use session-modified files (placeholder: empty until session tracking lands)
    #[arg(long)]
    pub session: bool,

    // === Analysis Options ===
    /// Maximum call graph traversal depth
    #[arg(long, short = 'd', default_value = "10")]
    pub depth: usize,

    /// Include import graph in analysis (not just call graph)
    #[arg(long, default_value = "true")]
    pub include_imports: bool,

    /// Custom test file patterns (comma-separated globs)
    #[arg(long, value_delimiter = ',')]
    pub test_patterns: Vec<String>,

    // === Output Options ===
    /// Output format override (backwards compatibility, prefer global --format/-f)
    #[arg(long = "output-format", short = 'o', hide = true)]
    pub output_format: Option<OutputFormat>,

    /// Output format for test runner integration
    #[arg(long, value_enum)]
    pub runner: Option<RunnerFormat>,

    /// Actually run the affected-test command (suppresses JSON; prints
    /// `Running: <cmd>` to stderr; propagates the child exit code)
    #[arg(long)]
    pub run: bool,
}

/// Test runner output formats
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RunnerFormat {
    /// pytest: space-separated test files
    Pytest,
    /// pytest with -k: pytest test_file.py::TestClass::test_func
    PytestK,
    /// jest --findRelatedTests format
    Jest,
    /// go test -run regex
    GoTest,
    /// cargo test filter
    CargoTest,
}

impl ChangeImpactArgs {
    /// Determine detection method based on CLI flags.
    ///
    /// Priority (preserves the pre-existing chain, slots --git/--session in):
    ///   explicit files > --base > --git/--git-base > --staged > --uncommitted
    ///   > --session > HEAD
    ///
    /// `--git` is Python-parity sugar for `GitBase { HEAD~1 }`. `--git-base
    /// <ref>` overrides that base (and implies git mode even without bare
    /// `--git`). Explicit `--base` still wins so the existing PR workflow is
    /// unchanged.
    fn determine_detection_method(&self) -> DetectionMethod {
        if !self.files.is_empty() {
            DetectionMethod::Explicit
        } else if let Some(base) = &self.base {
            DetectionMethod::GitBase { base: base.clone() }
        } else if self.git || self.git_base.is_some() {
            // Bare --git defaults to HEAD~1 (Python parity); --git-base
            // overrides the ref.
            let base = self
                .git_base
                .clone()
                .unwrap_or_else(|| "HEAD~1".to_string());
            DetectionMethod::GitBase { base }
        } else if self.staged {
            DetectionMethod::GitStaged
        } else if self.uncommitted {
            DetectionMethod::GitUncommitted
        } else if self.session {
            DetectionMethod::Session
        } else {
            DetectionMethod::GitHead
        }
    }

    /// Run the change-impact command
    pub fn run(&self, format: OutputFormat, quiet: bool) -> Result<()> {
        let writer = OutputWriter::new(self.output_format.unwrap_or(format), quiet);

        // cli-error-clarity-v2 (P2.BUG-4): reject regular files up-front so
        // callers don't get the cryptic "Git: Not a directory (os error 20)"
        // surfaced from the git invocation downstream.
        require_directory(&self.path, "change-impact")?;

        // Determine language (auto-detect from directory, default to Python)
        let language = self
            .lang
            .unwrap_or_else(|| Language::from_directory(&self.path).unwrap_or(Language::Python));

        // Determine detection method based on flags
        let detection = self.determine_detection_method();

        writer.progress(&format!(
            "Detecting changes via {} for {:?} in {}...",
            detection,
            language,
            self.path.display()
        ));

        // Prepare explicit files if provided
        let explicit_files = if !self.files.is_empty() {
            Some(self.files.clone())
        } else {
            None
        };

        // Call core change_impact_extended function
        let report = change_impact_extended(
            &self.path,
            detection,
            language,
            self.depth,
            self.include_imports,
            &self.test_patterns,
            explicit_files,
        )?;

        // --run: actually execute the affected-test command. Suppresses JSON
        // (Python parity), prints `Running: <cmd>` to STDERR, runs the argv
        // with no shell (injection-safe), inheriting stdout/stderr. Unlike
        // Python v1.5.2 (which discards the status), we PROPAGATE the child
        // exit code so `&&` chains and CI gates see real test failures
        // (intentional parity-PLUS).
        if self.run {
            if let Some(cmd) = &report.test_command {
                // The affected-test paths in `cmd` are project-relative
                // (e.g. `tests/test_x.py`), so the child must run WITH its
                // cwd set to the project root — otherwise pytest, spawned
                // from tldr's own cwd, cannot find the files.
                run_affected_tests(cmd, &self.path);
                // run_affected_tests never returns (it process::exit's).
            }
            // No test_command (unsupported language / failure state): fall
            // through to normal JSON/error handling below so the user still
            // sees why nothing ran.
        }

        // Output based on format/runner — always emit the report (including
        // failure states) so JSON consumers see the new `status` field.
        if let Some(runner) = self.runner {
            let runner_output = format_for_runner(&report, runner);
            println!("{}", runner_output);
        } else if writer.is_text() {
            let text = format_change_impact_text(&report);
            writer.write_text(&text)?;
        } else {
            writer.write(&report)?;
        }

        // Map failure states to a distinct exit code so shell callers can
        // distinguish "no baseline" from "no changes" without parsing JSON.
        match &report.status {
            ChangeImpactStatus::Completed | ChangeImpactStatus::NoChanges => Ok(()),
            ChangeImpactStatus::NoBaseline { reason } => {
                eprintln!(
                    "ERROR: change-impact: no baseline ({reason}). Try --files <path> or --base <ref>."
                );
                std::process::exit(3);
            }
            ChangeImpactStatus::DetectionFailed { reason } => {
                eprintln!(
                    "ERROR: change-impact: detection failed ({reason}). Try --files <path> or --base <ref>."
                );
                std::process::exit(3);
            }
        }
    }
}

/// Format an argv as a shell-display string for the `Running:` notice.
///
/// Mirrors Python's `shlex.join`: quote any token containing whitespace or a
/// shell metacharacter. Used ONLY for the human-facing stderr line — the
/// actual spawn uses the argv list directly (no shell), so this is purely
/// cosmetic and never feeds back into execution.
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty()
                || a.chars()
                    .any(|c| c.is_whitespace() || "\"'\\$`&|;<>()*?[]{}!#~".contains(c))
            {
                format!("'{}'", a.replace('\'', r"'\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Execute the affected-test command and propagate its exit code.
///
/// Python parity (cli.py:1237-1245): print `Running: <cmd>` to STDERR, then
/// spawn the argv with NO shell, inheriting stdout/stderr. The child runs WITH
/// its cwd set to `project` so the project-relative test paths resolve.
/// Parity-PLUS: we also propagate the child's exit code (Python v1.5.2
/// discards it). Never returns — always `process::exit`s with the child status
/// (or 127 if the command could not be spawned).
fn run_affected_tests(cmd: &[String], project: &std::path::Path) -> ! {
    eprintln!("Running: {}", shell_join(cmd));

    if cmd.is_empty() {
        eprintln!("ERROR: change-impact --run: empty test command");
        std::process::exit(127);
    }

    let status = std::process::Command::new(&cmd[0])
        .args(&cmd[1..])
        .current_dir(project)
        // stdout/stderr/stdin are inherited by default — the child's pytest
        // session output streams straight through to the user's terminal.
        .status();

    match status {
        Ok(status) => {
            // Propagate the exit code (parity-PLUS). On Unix a signal-killed
            // child has no code(); map that to 128 + signal-ish 1.
            std::process::exit(status.code().unwrap_or(1));
        }
        Err(e) => {
            eprintln!(
                "ERROR: change-impact --run: failed to spawn '{}': {}",
                cmd[0], e
            );
            std::process::exit(127);
        }
    }
}

/// Format report for specific test runner
fn format_for_runner(report: &ChangeImpactReport, runner: RunnerFormat) -> String {
    match runner {
        RunnerFormat::Pytest => {
            // Space-separated test file paths
            report
                .affected_tests
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(" ")
        }
        RunnerFormat::PytestK => {
            // pytest file::class::function format
            if report.affected_test_functions.is_empty() {
                // Fall back to file-level if no function extraction
                report
                    .affected_tests
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                report
                    .affected_test_functions
                    .iter()
                    .map(|tf| {
                        if let Some(ref class) = tf.class {
                            format!("{}::{}::{}", tf.file.display(), class, tf.function)
                        } else {
                            format!("{}::{}", tf.file.display(), tf.function)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            }
        }
        RunnerFormat::Jest => {
            // --findRelatedTests format (uses changed files, not test files)
            if report.changed_files.is_empty() {
                String::new()
            } else {
                format!(
                    "--findRelatedTests {}",
                    report
                        .changed_files
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            }
        }
        RunnerFormat::GoTest => {
            // go test -run "TestA|TestB" format
            // Extract test function names from affected_functions that look like tests
            let test_names: Vec<String> = report
                .affected_functions
                .iter()
                .filter(|f| f.name.starts_with("Test"))
                .map(|f| f.name.clone())
                .collect();

            if test_names.is_empty() {
                String::new()
            } else {
                format!("-run \"{}\"", test_names.join("|"))
            }
        }
        RunnerFormat::CargoTest => {
            // cargo test filter names (test function names)
            let test_names: Vec<String> = report
                .affected_functions
                .iter()
                .filter(|f| f.name.starts_with("test_"))
                .map(|f| f.name.clone())
                .collect();

            test_names.join(" ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_args(
        base: Option<String>,
        staged: bool,
        uncommitted: bool,
        files: Vec<PathBuf>,
    ) -> ChangeImpactArgs {
        ChangeImpactArgs {
            path: PathBuf::from("."),
            lang: None,
            files,
            base,
            git: false,
            git_base: None,
            staged,
            uncommitted,
            session: false,
            depth: 10,
            include_imports: true,
            test_patterns: vec![],
            output_format: None,
            runner: None,
            run: false,
        }
    }

    #[test]
    fn test_args_default_path() {
        let args = make_args(None, false, false, vec![]);
        assert_eq!(args.path, PathBuf::from("."));
    }

    #[test]
    fn test_args_with_explicit_files() {
        let args = make_args(
            None,
            false,
            false,
            vec![PathBuf::from("auth.py"), PathBuf::from("utils.py")],
        );
        assert_eq!(args.files.len(), 2);
    }

    #[test]
    fn test_detection_method_priority_explicit() {
        // Explicit files take highest priority
        let args = make_args(
            Some("main".to_string()),
            true,
            true,
            vec![PathBuf::from("file.py")],
        );
        assert_eq!(args.determine_detection_method(), DetectionMethod::Explicit);
    }

    #[test]
    fn test_detection_method_priority_base() {
        // --base takes priority over staged/uncommitted
        let args = make_args(Some("origin/main".to_string()), true, true, vec![]);
        match args.determine_detection_method() {
            DetectionMethod::GitBase { base } => assert_eq!(base, "origin/main"),
            _ => panic!("Expected GitBase"),
        }
    }

    #[test]
    fn test_detection_method_priority_staged() {
        // --staged takes priority over --uncommitted
        let args = make_args(None, true, true, vec![]);
        assert_eq!(
            args.determine_detection_method(),
            DetectionMethod::GitStaged
        );
    }

    #[test]
    fn test_detection_method_priority_uncommitted() {
        let args = make_args(None, false, true, vec![]);
        assert_eq!(
            args.determine_detection_method(),
            DetectionMethod::GitUncommitted
        );
    }

    #[test]
    fn test_detection_method_default_head() {
        let args = make_args(None, false, false, vec![]);
        assert_eq!(args.determine_detection_method(), DetectionMethod::GitHead);
    }

    // === Area 6 migration: --git / --git-base / --session detection ===

    /// Bare `--git` maps to GitBase { HEAD~1 } (Python parity).
    #[test]
    fn test_detection_method_git_defaults_to_head_tilde_1() {
        let mut args = make_args(None, false, false, vec![]);
        args.git = true;
        match args.determine_detection_method() {
            DetectionMethod::GitBase { base } => assert_eq!(base, "HEAD~1"),
            other => panic!("expected GitBase HEAD~1, got {:?}", other),
        }
    }

    /// `--git --git-base origin/main` overrides the base ref.
    #[test]
    fn test_detection_method_git_base_override() {
        let mut args = make_args(None, false, false, vec![]);
        args.git = true;
        args.git_base = Some("origin/main".to_string());
        match args.determine_detection_method() {
            DetectionMethod::GitBase { base } => assert_eq!(base, "origin/main"),
            other => panic!("expected GitBase origin/main, got {:?}", other),
        }
    }

    /// `--git-base <ref>` alone (without bare --git) still implies git mode.
    #[test]
    fn test_detection_method_git_base_implies_git_mode() {
        let mut args = make_args(None, false, false, vec![]);
        args.git_base = Some("v1.0.0".to_string());
        match args.determine_detection_method() {
            DetectionMethod::GitBase { base } => assert_eq!(base, "v1.0.0"),
            other => panic!("expected GitBase v1.0.0, got {:?}", other),
        }
    }

    /// `--session` maps to DetectionMethod::Session (lower priority than git).
    #[test]
    fn test_detection_method_session() {
        let mut args = make_args(None, false, false, vec![]);
        args.session = true;
        assert_eq!(args.determine_detection_method(), DetectionMethod::Session);
    }

    /// Explicit `--base` still wins over `--git` (priority preserved).
    #[test]
    fn test_detection_method_base_wins_over_git() {
        let mut args = make_args(Some("develop".to_string()), false, false, vec![]);
        args.git = true;
        args.git_base = Some("HEAD~5".to_string());
        match args.determine_detection_method() {
            DetectionMethod::GitBase { base } => assert_eq!(base, "develop"),
            other => panic!("expected explicit --base develop to win, got {:?}", other),
        }
    }

    /// Full priority chain: files > base > git > staged > uncommitted >
    /// session > head.
    #[test]
    fn test_detection_method_full_priority_chain() {
        // git beats staged/uncommitted/session
        let mut args = make_args(None, true, true, vec![]);
        args.git = true;
        args.session = true;
        match args.determine_detection_method() {
            DetectionMethod::GitBase { base } => assert_eq!(base, "HEAD~1"),
            other => panic!("git should beat staged/uncommitted/session, got {:?}", other),
        }

        // uncommitted beats session
        let mut args = make_args(None, false, true, vec![]);
        args.session = true;
        assert_eq!(
            args.determine_detection_method(),
            DetectionMethod::GitUncommitted
        );

        // session beats head
        let mut args = make_args(None, false, false, vec![]);
        args.session = true;
        assert_eq!(args.determine_detection_method(), DetectionMethod::Session);
    }

    /// shell_join quotes tokens with whitespace/metacharacters (cosmetic
    /// `Running:` line only; the actual spawn uses the argv list).
    #[test]
    fn test_shell_join_quoting() {
        assert_eq!(
            shell_join(&["pytest".to_string(), "tests/test_a.py".to_string()]),
            "pytest tests/test_a.py"
        );
        assert_eq!(
            shell_join(&["pytest".to_string(), "a b.py".to_string()]),
            "pytest 'a b.py'"
        );
        // Embedded single quote is escaped.
        assert_eq!(
            shell_join(&["echo".to_string(), "it's".to_string()]),
            r#"echo 'it'\''s'"#
        );
    }

    #[test]
    fn test_format_pytest() {
        let report = ChangeImpactReport {
            changed_files: vec![PathBuf::from("src/auth.py")],
            affected_tests: vec![
                PathBuf::from("tests/test_auth.py"),
                PathBuf::from("tests/test_utils.py"),
            ],
            affected_test_functions: vec![],
            affected_functions: vec![],
            detection_method: "explicit".to_string(),
            metadata: None,
            status: tldr_core::ChangeImpactStatus::Completed,
            ..Default::default()
        };

        let output = format_for_runner(&report, RunnerFormat::Pytest);
        assert_eq!(output, "tests/test_auth.py tests/test_utils.py");
    }

    #[test]
    fn test_format_jest() {
        let report = ChangeImpactReport {
            changed_files: vec![PathBuf::from("src/auth.ts"), PathBuf::from("src/utils.ts")],
            affected_tests: vec![],
            affected_test_functions: vec![],
            affected_functions: vec![],
            detection_method: "explicit".to_string(),
            metadata: None,
            status: tldr_core::ChangeImpactStatus::Completed,
            ..Default::default()
        };

        let output = format_for_runner(&report, RunnerFormat::Jest);
        assert_eq!(output, "--findRelatedTests src/auth.ts src/utils.ts");
    }

    #[test]
    fn test_format_pytest_k_with_functions() {
        use tldr_core::TestFunction;

        let report = ChangeImpactReport {
            changed_files: vec![PathBuf::from("src/auth.py")],
            affected_tests: vec![PathBuf::from("tests/test_auth.py")],
            affected_test_functions: vec![
                TestFunction {
                    file: PathBuf::from("tests/test_auth.py"),
                    function: "test_login".to_string(),
                    class: Some("TestAuth".to_string()),
                    line: 10,
                },
                TestFunction {
                    file: PathBuf::from("tests/test_auth.py"),
                    function: "test_logout".to_string(),
                    class: None,
                    line: 20,
                },
            ],
            affected_functions: vec![],
            detection_method: "explicit".to_string(),
            metadata: None,
            status: tldr_core::ChangeImpactStatus::Completed,
            ..Default::default()
        };

        let output = format_for_runner(&report, RunnerFormat::PytestK);
        assert!(output.contains("tests/test_auth.py::TestAuth::test_login"));
        assert!(output.contains("tests/test_auth.py::test_logout"));
    }
}
