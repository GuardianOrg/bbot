import regex as re


def sanitize_git_repo(repo_folder):
    # sanitizing the git config is infeasible since there are too many different ways to do evil things
    # instead, we move it out of .git and into the repo folder, so we don't miss any secrets etc. inside
    config_file = repo_folder / ".git" / "config"
    if config_file.exists():
        config_file.rename(repo_folder / "git_config")
    # remove the index file
    index_file = repo_folder / ".git" / "index"
    index_file.unlink(missing_ok=True)
