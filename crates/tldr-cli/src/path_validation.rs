//! Path validation helpers for CLI commands.
//!
//! cli-error-clarity-v2 (P2.BUG-4): commands that operate on a project
//! directory (hubs, impact, whatbreaks, change-impact, …) historically
//! produced confusing errors when given a regular file:
//!
//! - `tldr hubs <file>` → `Error: Path not found: <file>` (false: it exists)
//! - `tldr change-impact <file>` → `Git: Not a directory (os error 20)`
//!   (cryptic; the user has no idea what to do)
//!
//! These helpers normalise the validation so every directory-taking command
//! returns the same clear, actionable error mentioning the file path and
//! suggesting the project root.
//!
//! All helpers return `anyhow::Error` so they can be used directly with the
//! `?` operator inside `run()` methods that already return
//! `anyhow::Result<()>`.

use std::path::Path;

use anyhow::{bail, Result};

/// Validate that `path` exists and is a directory, producing clear error
/// messages on failure.
///
/// `command` is the CLI subcommand name (e.g. `"hubs"`) used to make the
/// error message specific.
pub fn require_directory(path: &Path, command: &str) -> Result<()> {
    if !path.exists() {
        bail!("Path not found: {}", path.display());
    }
    if path.is_file() {
        bail!(
            "{} requires a directory; got file '{}'. Pass the project root \
             or omit the argument to use the current directory.",
            command,
            path.display()
        );
    }
    if !path.is_dir() {
        bail!(
            "{} requires a directory; got non-directory path '{}'. Pass the \
             project root or omit the argument to use the current directory.",
            command,
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn directory_passes() {
        let dir = tempdir().unwrap();
        require_directory(dir.path(), "hubs").unwrap();
    }

    #[test]
    fn file_fails_with_clear_message() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("a.py");
        fs::write(&file, "x = 1\n").unwrap();
        let err = require_directory(&file, "hubs").unwrap_err().to_string();
        assert!(err.contains("hubs requires a directory"), "{}", err);
        assert!(err.contains(file.to_string_lossy().as_ref()), "{}", err);
    }

    #[test]
    fn missing_path_fails() {
        let err = require_directory(Path::new("/no/such/path/xyz"), "hubs")
            .unwrap_err()
            .to_string();
        assert!(err.contains("Path not found"), "{}", err);
    }
}
