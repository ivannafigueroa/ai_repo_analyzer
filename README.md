# compliance-test1

This repository includes a script `ai_repo_analyzer.py` that scans a git
repository for vulnerabilities inspired by several OWASP lists. It performs
simple heuristic checks and, when an `OPENAI_API_KEY` environment variable is
available, also sends code snippets to the OpenAI API for deeper analysis.

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
scanning to ensure the original files are left untouched. To enable AI-powered
analysis, set the `OPENAI_API_KEY` environment variable before running the
script.
