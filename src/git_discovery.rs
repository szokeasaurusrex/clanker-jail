use std::fs;
use std::path::{Path, PathBuf};

/// Returns the git directories relevant to `cwd` using filesystem discovery.
///
/// For a plain checkout this returns the `.git` directory once.
/// For a linked worktree it returns both the per-worktree git dir and the
/// shared common dir so sandboxed git commands can read and write both.
///
/// Returns an empty vec if `cwd` is not inside a git repo.
pub fn discover_git_dirs(cwd: &Path) -> Vec<PathBuf> {
    discover_git_dir(cwd)
        .map(|git_dir| {
            std::iter::once(git_dir.clone())
                .chain(discover_common_git_dir(&git_dir))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn discover_git_dir(cwd: &Path) -> Option<PathBuf> {
    cwd.ancestors().find_map(|ancestor| {
        let git_entry = ancestor.join(".git");
        if git_entry.is_dir() {
            canonical_or_absolute(&git_entry).ok()
        } else if git_entry.is_file() {
            read_gitdir_pointer(&git_entry, ancestor)
        } else {
            None
        }
    })
}

fn read_gitdir_pointer(git_entry: &Path, fallback_base: &Path) -> Option<PathBuf> {
    fs::read_to_string(git_entry)
        .ok()
        .and_then(|contents| contents.lines().next().map(str::trim).map(str::to_owned))
        .and_then(|line| {
            line.strip_prefix("gitdir:")
                .map(str::trim)
                .map(str::to_owned)
        })
        .filter(|raw_path| !raw_path.is_empty())
        .map(|raw_path| {
            resolve_git_path(
                raw_path.as_ref(),
                git_entry.parent().unwrap_or(fallback_base),
            )
        })
        .and_then(|resolved| canonical_or_absolute(&resolved).ok())
}

fn discover_common_git_dir(git_dir: &Path) -> Option<PathBuf> {
    let commondir = git_dir.join("commondir");
    fs::read_to_string(&commondir)
        .ok()
        .and_then(|contents| contents.lines().next().map(str::trim).map(str::to_owned))
        .map(|raw_path| match raw_path.as_str() {
            "" | "." => git_dir.to_path_buf(),
            _ => resolve_git_path(raw_path.as_ref(), git_dir),
        })
        .and_then(|resolved| canonical_or_absolute(&resolved).ok())
}

fn canonical_or_absolute(path: &Path) -> std::io::Result<PathBuf> {
    match (path.exists(), path.is_absolute()) {
        (true, _) => path.canonicalize(),
        (false, true) => Ok(path.to_path_buf()),
        (false, false) => std::env::current_dir().map(|cwd| cwd.join(path)),
    }
}

fn resolve_git_path(raw_path: &Path, base_dir: &Path) -> PathBuf {
    if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        base_dir.join(raw_path)
    }
}

#[cfg(test)]
mod tests {
    use super::discover_git_dirs;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn discovers_plain_checkout_git_dir() {
        let root = temp_dir("plain-checkout");
        let repo = root.join("repo");
        let worktree = repo.join("subdir");
        fs::create_dir_all(&worktree).expect("create repo");
        fs::create_dir_all(repo.join(".git")).expect("create git dir");

        let dirs = discover_git_dirs(&worktree);

        assert_eq!(dirs, vec![canonical(&repo.join(".git"))]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discovers_worktree_git_and_common_dirs() {
        let root = temp_dir("worktree");
        let worktree_root = root.join("checkout");
        let worktree_git = root.join("worktree-git");
        let common_git = root.join("common-git");
        let worktree_subdir = worktree_root.join("src");
        fs::create_dir_all(&worktree_subdir).expect("create worktree");
        fs::create_dir_all(&worktree_git).expect("create worktree git");
        fs::create_dir_all(&common_git).expect("create common git");

        fs::write(
            worktree_root.join(".git"),
            format!("gitdir: {}\n", worktree_git.display()),
        )
        .expect("write gitdir file");
        fs::write(
            worktree_git.join("commondir"),
            format!("{}\n", common_git.display()),
        )
        .expect("write commondir file");

        let dirs = discover_git_dirs(&worktree_subdir);

        assert_eq!(dirs, vec![canonical(&worktree_git), canonical(&common_git)]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn returns_empty_when_not_in_repo() {
        let root = temp_dir("not-in-repo");
        let cwd = root.join("cwd");
        fs::create_dir_all(&cwd).expect("create cwd");

        let dirs = discover_git_dirs(&cwd);

        assert!(dirs.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    fn temp_dir(label: &str) -> PathBuf {
        let mut dir = env::temp_dir();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        dir.push(format!("clanker-jail-{label}-{stamp}"));
        dir
    }

    fn canonical(path: &Path) -> PathBuf {
        path.canonicalize().expect("canonicalize path")
    }
}
