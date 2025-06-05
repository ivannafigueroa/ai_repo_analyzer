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

try:
    import openai  # Optional, used for AI-powered analysis
except ImportError:
    openai = None

OWASP_DESCRIPTIONS = {
    "INJECTION": "Code constructs that allow injection of commands or queries.",
    "HARDCODED_SECRET": "Secrets such as passwords or API keys appear hardcoded in code.",
    "INSECURE_DESERIALIZATION": "Use of deserialization libraries known to be unsafe.",
    "LLM_UNVALIDATED_INPUT": "Inputs from untrusted sources sent directly to LLM calls.",
    "OVERLY_BROAD_OS_PERMS": "Agent code executes OS commands or file operations without restrictions.",
}

RULES = [
    # OWASP Top 10 for Applications
    {
        "name": "A01_BROKEN_ACCESS_CONTROL",
        "pattern": re.compile(r"is_admin|role\s*=\s*['\"]admin['\"]"),
        "description": "Potential broken access control logic detected.",
        "exploitation": "Attackers may manipulate role checks to gain unauthorized access.",
        "mitigation": [
            "Enforce server side access controls on every request.",
            "Audit authorization logic for inconsistencies.",
        ],
    },
    {
        "name": "A02_CRYPTOGRAPHIC_FAILURES",
        "pattern": re.compile(r"md5\(|sha1\(|http:\/\/"),
        "description": "Weak cryptography or insecure transport detected.",
        "exploitation": "Attackers may break weak hashes or sniff plaintext traffic.",
        "mitigation": [
            "Use modern algorithms like SHA-256 and enforce HTTPS.",
        ],
    },
    {
        "name": "A03_INJECTION",
        "pattern": re.compile(r"\b(exec|eval|system|popen)\b"),
        "description": "Use of dynamic execution functions can lead to command injection.",
        "exploitation": "Attacker supplies malicious input that gets executed directly, running arbitrary commands.",
        "mitigation": [
            "Avoid dynamic execution where possible and sanitize inputs.",
        ],
    },
    {
        "name": "A04_INSECURE_DESIGN",
        "pattern": re.compile(r"insecure_design", re.IGNORECASE),
        "description": "Code contains markers indicating insecure design choices.",
        "exploitation": "Poorly designed features can be abused in unforeseen ways.",
        "mitigation": [
            "Perform threat modeling and design reviews.",
        ],
    },
    {
        "name": "A05_SECURITY_MISCONFIGURATION",
        "pattern": re.compile(r"DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*"),
        "description": "Debug mode or overly permissive configuration detected.",
        "exploitation": "Attackers can gather sensitive debug info or abuse misconfigurations.",
        "mitigation": [
            "Disable debug features in production and limit allowed hosts.",
        ],
    },
    {
        "name": "A06_VULNERABLE_COMPONENTS",
        "pattern": re.compile(r"jquery-1\.|django==1\."),
        "description": "Use of outdated third party components detected.",
        "exploitation": "Known vulnerabilities in old components may be exploited.",
        "mitigation": [
            "Update dependencies to maintained versions.",
        ],
    },
    {
        "name": "A07_IDENTIFICATION_FAILURES",
        "pattern": re.compile(r"verify=False|password\s*==\s*input"),
        "description": "Potential authentication weaknesses.",
        "exploitation": "Attackers may bypass authentication or intercept credentials.",
        "mitigation": [
            "Use strong authentication mechanisms and enforce TLS certificate validation.",
        ],
    },
    {
        "name": "A08_INTEGRITY_FAILURES",
        "pattern": re.compile(r"curl .*\|\s*sh"),
        "description": "Code downloads and executes remote resources directly.",
        "exploitation": "Remote scripts may be replaced with malicious versions to gain control.",
        "mitigation": [
            "Verify downloads with cryptographic signatures.",
        ],
    },
    {
        "name": "A09_LOGGING_MONITORING_FAILURES",
        "pattern": re.compile(r"logging.disable\(|pass\s+#\s*no\s*log"),
        "description": "Logging is disabled or errors are silently ignored.",
        "exploitation": "Attackers can operate without detection if monitoring is absent.",
        "mitigation": [
            "Ensure security events are logged and monitored.",
        ],
    },
    {
        "name": "A10_SSRF",
        "pattern": re.compile(r"requests.get\(|urllib.request"),
        "description": "Possible server-side request forgery via user supplied URLs.",
        "exploitation": "Attacker could leverage the server to access internal resources.",
        "mitigation": [
            "Validate and restrict destination URLs.",
        ],
    },

    # OWASP Top 10 Agentic Threats (simplified heuristics)
    {
        "name": "AGT01_PROMPT_INJECTION",
        "pattern": re.compile(r"{\s*user_input\s*}"),
        "description": "User input directly embedded in prompts.",
        "exploitation": "Malicious input could alter agent behavior or leak data.",
        "mitigation": [
            "Sanitize and contextually escape user provided prompt fragments.",
        ],
    },
    {
        "name": "AGT02_DATA_EXFILTRATION",
        "pattern": re.compile(r"upload\(|send\(|post\("),
        "description": "Code that sends data to external destinations.",
        "exploitation": "Agent may transmit sensitive data to attacker controlled servers.",
        "mitigation": [
            "Restrict network access and audit data leaving the system.",
        ],
    },
    {
        "name": "AGT03_PRIVACY_VIOLATION",
        "pattern": re.compile(r"ssn|social_security_number|credit_card"),
        "description": "Potential handling of personal identifiable information.",
        "exploitation": "Leakage of private user data violates privacy regulations.",
        "mitigation": [
            "Redact or encrypt personal data and limit retention.",
        ],
    },
    {
        "name": "AGT04_UNAUTHORIZED_CODE_EXECUTION",
        "pattern": re.compile(r"eval\(|exec\("),
        "description": "Dynamic code execution without strict controls.",
        "exploitation": "Agent may execute attacker supplied code.",
        "mitigation": [
            "Avoid eval/exec or heavily restrict allowed inputs.",
        ],
    },
    {
        "name": "AGT05_AUTONOMOUS_REPLICATION",
        "pattern": re.compile(r"self\.replicate\(|git clone"),
        "description": "Code attempting to copy or clone itself automatically.",
        "exploitation": "Self-replication can lead to uncontrollable spread of the agent.",
        "mitigation": [
            "Disable self-replication features and require approvals for deployments.",
        ],
    },
    {
        "name": "AGT06_RESOURCE_EXHAUSTION",
        "pattern": re.compile(r"while\s+True|for\s+\d+\s+in\s+range\(\d{9}"),
        "description": "Code contains potentially endless or huge loops.",
        "exploitation": "Malicious prompts could trigger heavy loops causing denial of service.",
        "mitigation": [
            "Apply quotas and timeouts to loops and resource intensive tasks.",
        ],
    },
    {
        "name": "AGT07_SELF_MODIFICATION",
        "pattern": re.compile(r"open\(__file__, 'w"),
        "description": "Agent attempts to modify its own source code.",
        "exploitation": "Self-modifying code can be manipulated to insert malicious logic.",
        "mitigation": [
            "Make source directories read-only at runtime.",
        ],
    },
    {
        "name": "AGT08_PRIVILEGE_ESCALATION",
        "pattern": re.compile(r"sudo\s|setuid"),
        "description": "Calls that attempt to change privileges or run as sudo.",
        "exploitation": "Agent could gain higher privileges and compromise the host.",
        "mitigation": [
            "Drop unnecessary privileges and avoid invoking sudo.",
        ],
    },
    {
        "name": "AGT09_SOCIAL_ENGINEERING",
        "pattern": re.compile(r"click here|free money", re.IGNORECASE),
        "description": "Suspicious messaging patterns that could be social engineering.",
        "exploitation": "Users may be tricked into performing risky actions.",
        "mitigation": [
            "Filter deceptive phrases from generated content.",
        ],
    },
    {
        "name": "AGT10_MISINFORMATION",
        "pattern": re.compile(r"fake news|unverified"),
        "description": "Content that may propagate misinformation.",
        "exploitation": "Agent might spread false narratives intentionally or unintentionally.",
        "mitigation": [
            "Cross-check facts and cite reputable sources.",
        ],
    },

    # OWASP Top 10 for LLM Applications (simplified heuristics)
    {
        "name": "LLM01_PROMPT_INJECTION",
        "pattern": re.compile(r"{\s*user_input\s*}", re.IGNORECASE),
        "description": "Prompt contains user supplied content without sanitization.",
        "exploitation": "Attackers manipulate prompts to make the model act unsafely.",
        "mitigation": [
            "Escape or filter user provided prompt segments before use.",
        ],
    },
    {
        "name": "LLM02_INSECURE_OUTPUT_HANDLING",
        "pattern": re.compile(r"eval\(response|exec\(response"),
        "description": "LLM response is executed as code without validation.",
        "exploitation": "Malicious LLM output could run arbitrary commands.",
        "mitigation": [
            "Never directly execute LLM outputs without review.",
        ],
    },
    {
        "name": "LLM03_TRAINING_DATA_POISONING",
        "pattern": re.compile(r"untrusted_training_data"),
        "description": "Model trained on unverified data sources.",
        "exploitation": "Malicious training data can embed backdoors or biases.",
        "mitigation": [
            "Vet datasets and monitor for data manipulation.",
        ],
    },
    {
        "name": "LLM04_MODEL_DOS",
        "pattern": re.compile(r"large_language_model\s*\*\s*\d+"),
        "description": "Loops or code that repeatedly calls the model excessively.",
        "exploitation": "May exhaust API quotas and deny service to others.",
        "mitigation": [
            "Rate limit calls to language models.",
        ],
    },
    {
        "name": "LLM05_SUPPLY_CHAIN",
        "pattern": re.compile(r"pip install .*--extra-index-url"),
        "description": "Using untrusted package indexes for dependencies.",
        "exploitation": "Attackers could supply malicious packages via rogue indexes.",
        "mitigation": [
            "Pin dependencies and verify package sources.",
        ],
    },
    {
        "name": "LLM06_DATA_LEAKAGE",
        "pattern": re.compile(r"print\(.*password|log\(.*secret"),
        "description": "Model or code prints sensitive information.",
        "exploitation": "Logs or outputs may reveal confidential data to attackers.",
        "mitigation": [
            "Mask or remove secrets from logs and outputs.",
        ],
    },
    {
        "name": "LLM07_INSECURE_PLUGIN_DESIGN",
        "pattern": re.compile(r"plugin\.register\(.*unsafe"),
        "description": "Plugin registration includes unsafe capabilities.",
        "exploitation": "Malicious plugins may take over agent operations.",
        "mitigation": [
            "Review plugins for least privilege before enabling.",
        ],
    },
    {
        "name": "LLM08_EXCESSIVE_AGENCY",
        "pattern": re.compile(r"allow_autonomous_actions=True"),
        "description": "Agent configured for broad autonomous actions.",
        "exploitation": "Overly autonomous agents may perform unintended operations.",
        "mitigation": [
            "Limit autonomy and require human approval for sensitive tasks.",
        ],
    },
    {
        "name": "LLM09_OVERRELIANCE",
        "pattern": re.compile(r"trust_the_model"),
        "description": "Code comments indicate blind trust of model output.",
        "exploitation": "Developers may accept incorrect answers leading to vulnerabilities.",
        "mitigation": [
            "Implement human oversight and validation of critical decisions.",
        ],
    },
    {
        "name": "LLM10_MODEL_THEFT",
        "pattern": re.compile(r"download_model\(|model\.save"),
        "description": "Model files may be copied or exfiltrated.",
        "exploitation": "Attackers could steal proprietary models from the system.",
        "mitigation": [
            "Encrypt model files and restrict access permissions.",
        ],
    },
    {
        "name": "HARDCODED_SECRET",
        "pattern": re.compile(r"(password|api[_-]?key|secret)\s*=\s*['\"]"),
        "description": "Hardcoded credentials expose sensitive data and may allow attackers access.",
        "exploitation": "An attacker reading the repo can use the exposed secret to access protected resources.",
        "mitigation": [
            "Move secrets to environment variables or a secure vault.",
            "Ensure they are not committed to source control.",
        ],
    },
    {
        "name": "INSECURE_DESERIALIZATION",
        "pattern": re.compile(r"\b(pickle\.loads|yaml\.load)\b"),
        "description": "Unsafe deserialization can allow arbitrary code execution.",
        "exploitation": "Supplying crafted serialized data can execute arbitrary Python when deserialized.",
        "mitigation": [
            "Use safe alternatives such as json or yaml.safe_load.",
            "Do not deserialize untrusted data.",
        ],
    },
    {
        "name": "LLM_UNVALIDATED_INPUT",
        "pattern": re.compile(r"openai\.|anthropic\.|llm"),
        "description": "Potential LLM call without input validation detected.",
        "exploitation": "Untrusted input could coerce the LLM into revealing sensitive data or performing unintended actions.",
        "mitigation": [
            "Validate and sanitize user input before sending it to an LLM.",
            "Implement output filtering on LLM responses.",
        ],
    },
    {
        "name": "OVERLY_BROAD_OS_PERMS",
        "pattern": re.compile(r"subprocess\.run|os\.remove|os\.rmdir"),
        "description": "Agent code executing OS commands; ensure least privilege.",
        "exploitation": "Attacker may leverage these calls to delete or modify system files or run commands.",
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
        if ".git" in root.split(os.sep):
            continue
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
                "exploitation": rule.get("exploitation", ""),
                "mitigation": rule["mitigation"],
                "file": path,
            })

    # Optionally send file content to OpenAI for deeper analysis
    if openai is not None and os.getenv("OPENAI_API_KEY"):
        openai.api_key = os.getenv("OPENAI_API_KEY")
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a security analyst identifying vulnerabilities in source code. "
                    "Return a JSON array where each element has keys: vulnerability, description, "
                    "exploitation, and mitigation. Use OWASP Top 10, Agentic Threats, and LLM "
                    "guidelines where relevant."
                ),
            },
            {
                "role": "user",
                "content": f"Analyze the following code from {path}:\n\n{content[:3000]}",
            },
        ]
        try:
            resp = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=messages,
                temperature=0,
            )
            ai_output = resp.choices[0].message.content
            try:
                ai_findings = json.loads(ai_output)
                for item in ai_findings:
                    item["file"] = path
                    results.append(item)
            except json.JSONDecodeError:
                results.append({"file": path, "error": "Failed to parse OpenAI response", "raw": ai_output})
        except Exception as exc:
            results.append({"file": path, "error": str(exc)})
    return results


def analyze_repo(repo_path: str) -> List[Dict[str, str]]:
    all_findings = []
    for file in list_files(repo_path):
        findings = scan_file(file)
        all_findings.extend(findings)
    return all_findings


def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "."
        print("No target provided, analyzing current directory")
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
