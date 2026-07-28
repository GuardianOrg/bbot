from pathlib import Path


_SAFE_GIT_CONFIG = """\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
\tfsmonitor = false
\tsymlinks = false
\tsshCommand = echo
[transfer]
\tfsckObjects = true
"""


def sanitize_git_repo(repo_folder: Path):
    # Preserve the original for secret scanners, then replace it with a config
    # that disables executable hooks, external commands, symlinks, and fsmonitor.
    config_file = repo_folder / ".git" / "config"
    config_file.parent.mkdir(parents=True, exist_ok=True)
    if config_file.exists():
        config_file.rename(repo_folder / "git_config_original")
    config_file.write_text(_SAFE_GIT_CONFIG)
    # move the index file
    index_file = repo_folder / ".git" / "index"
    if index_file.exists():
        index_file.rename(repo_folder / "git_index_original")
    # move the hooks folder
    hooks_folder = repo_folder / ".git" / "hooks"
    if hooks_folder.exists():
        hooks_folder.rename(repo_folder / "git_hooks_original")
