# AI Repo Analyzer

This repository includes a script `ai_repo_analyzer.py` that scans a git
repository for vulnerabilities inspired by several OWASP lists. It performs
simple heuristic checks and, when an `OPENAI_API_KEY` environment variable is
available, also sends code snippets to the OpenAI API for deeper analysis.

## Usage

Provide a local path or git URL to analyze (use `.` for the current directory). If no argument is supplied, the analyzer defaults to the current directory:

```bash
python ai_repo_analyzer.py /path/to/repo
python ai_repo_analyzer.py   # analyze current directory
```

The script copies the repository to a temporary staging directory before
scanning to ensure the original files are left untouched. To enable AI-powered
analysis, set the `OPENAI_API_KEY` environment variable before running the
script.
