import regex as re

GIT_CONFIG_UNSAFE_REGEX = re.compile(r"^.*(?:fsmonitor|sshcommand|askpass|editor|pager)\s*=.+", re.IGNORECASE)


def sanitize_git_repo(repo_folder, remove_index=True):
    # sanitize git config, removing unsafe options that could be used to execute code
    config_file = repo_folder / ".git" / "config"
    if config_file.exists():
        with config_file.open("r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            sanitized = re.sub(GIT_CONFIG_UNSAFE_REGEX, r"# \g<0>", content)
        with config_file.open("w", encoding="utf-8") as file:
            file.write(sanitized)
    # remove the index file
    if remove_index:
        index_file = repo_folder / ".git" / "index"
        index_file.unlink(missing_ok=True)
