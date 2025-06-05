#!/usr/bin/env python3
"""AI Repo Analyzer

This script scans a git repository and reports potential security vulnerabilities.
The checks are inspired by the OWASP Top 10 for Applications, OWASP Agentic Threats
and OWASP Top 10 for LLMs. The analysis always runs on a temporary copy of the
repository so the original files are never modified.

This is not a replacement for a full security audit, but provides heuristics that
highlight suspicious patterns.
"""

import os
import re
import sys
import subprocess
import tempfile
import shutil
import json
from typing import List, Dict

OWASP_DESCRIPTIONS = {
    "INJECTION": "Code constructs that allow injection of commands or queries.",
    "HARDCODED_SECRET": "Secrets such as passwords or API keys appear hardcoded in code.",
    "INSECURE_DESERIALIZATION": "Use of deserialization libraries known to be unsafe.",
    "LLM_UNVALIDATED_INPUT": "Inputs from untrusted sources sent directly to LLM calls.",
    "OVERLY_BROAD_OS_PERMS": "Agent code executes OS commands or file operations without restrictions.",
}

RULES = [
    {
        "name": "INJECTION",
        "pattern": re.compile(r"\b(exec|eval|system|popen)\b"),
        "description": "Use of dynamic execution functions can lead to command injection.",
        "mitigation": [
            "Avoid using dynamic execution when possible.",
            "If needed, validate and sanitize all inputs used in these calls.",
        ],
    },
    {
        "name": "HARDCODED_SECRET",
        "pattern": re.compile(r"(password|api[_-]?key|secret)\s*=\s*['\"]"),
        "description": "Hardcoded credentials expose sensitive data and may allow attackers access.",
        "mitigation": [
            "Move secrets to environment variables or a secure vault.",
            "Ensure they are not committed to source control.",
        ],
    },
    {
        "name": "INSECURE_DESERIALIZATION",
        "pattern": re.compile(r"\b(pickle\.loads|yaml\.load)\b"),
        "description": "Unsafe deserialization can allow arbitrary code execution.",
        "mitigation": [
            "Use safe alternatives such as json or yaml.safe_load.",
            "Do not deserialize untrusted data.",
        ],
    },
    {
        "name": "LLM_UNVALIDATED_INPUT",
        "pattern": re.compile(r"openai\.|anthropic\.|llm"),
        "description": "Potential LLM call without input validation detected.",
        "mitigation": [
            "Validate and sanitize user input before sending it to an LLM.",
            "Implement output filtering on LLM responses.",
        ],
    },
    {
        "name": "OVERLY_BROAD_OS_PERMS",
        "pattern": re.compile(r"subprocess\.run|os\.remove|os\.rmdir"),
        "description": "Agent code executing OS commands; ensure least privilege.",
        "mitigation": [
            "Limit the commands and file paths the agent can access.",
            "Run the agent in a sandboxed environment if possible.",
        ],
    },
]


def clone_repo(repo_url: str) -> str:
    """Clone repo_url to a temporary directory and return the path."""
    tmpdir = tempfile.mkdtemp(prefix="repo_")
    subprocess.run(["git", "clone", repo_url, tmpdir], check=True)
    return tmpdir


def stage_local_repo(path: str) -> str:
    """Copy an existing repo to a temporary staging directory and return it."""
    staging_dir = tempfile.mkdtemp(prefix="stage_")
    shutil.copytree(path, staging_dir, dirs_exist_ok=True)
    return staging_dir


def list_files(repo_path: str) -> List[str]:
    """Return a list of source files under repo_path."""
    files = []
    for root, dirs, filenames in os.walk(repo_path):
        for name in filenames:
            if name.startswith("."):
                continue
            files.append(os.path.join(root, name))
    return files


def scan_file(path: str) -> List[Dict[str, str]]:
    """Scan a single file and return list of vulnerabilities found."""
    results = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return results

    for rule in RULES:
        if rule["pattern"].search(content):
            results.append({
                "vulnerability": rule["name"],
                "description": rule["description"],
                "mitigation": rule["mitigation"],
                "file": path,
            })
    return results


def analyze_repo(repo_path: str) -> List[Dict[str, str]]:
    all_findings = []
    for file in list_files(repo_path):
        findings = scan_file(file)
        all_findings.extend(findings)
    return all_findings


def main():
    if len(sys.argv) < 2:
        # Default to current directory when no argument is provided so the
        # script can be run without parameters, e.g. during quick checks.
        target = os.getcwd()
    else:
        target = sys.argv[1]
    cleanup = None

    if os.path.exists(target):
        repo_path = stage_local_repo(target)
        cleanup = repo_path
    else:
        repo_path = clone_repo(target)
        cleanup = repo_path

    findings = analyze_repo(repo_path)
    print(json.dumps(findings, indent=2))

    if cleanup:
        shutil.rmtree(cleanup)


if __name__ == "__main__":
    main()
