# compliance-test1

This repository includes a simple script `ai_repo_analyzer.py` that heuristically
scans a git repository for common vulnerabilities inspired by several OWASP
lists.

## Usage

Run the analyzer against the current directory:

```bash
python ai_repo_analyzer.py
```

Or specify a path or git URL to analyze:

```bash
python ai_repo_analyzer.py /path/to/repo
```

The script copies the repository to a temporary staging directory before
scanning to ensure the original files are left untouched.
