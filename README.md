# ReviewRadar

This project is a lightweight repository audit tool that scans a target project, gathers findings from multiple security and quality scanners, ranks the issues, and produces a PDF report.

The main script is `audit_repo.sh`.

## What this script does

Think of it like a home inspection for code:

- it inspects a Git repo, local folder, or single file
- it checks dependencies for known vulnerabilities
- it searches for secrets and exposed credentials
- it runs static analysis for risky code patterns
- it merges all results into one report
- it ranks issues by severity
- it writes a Markdown report and a PDF report

This is useful for quick security reviews, repository triage, and first-pass code auditing before deeper manual review.

## Supported targets

The script accepts:

- a Git URL
- a local folder
- a single file

Examples:

```bash
./audit_repo.sh https://github.com/juice-shop/juice-shop
./audit_repo.sh ./my-project
./audit_repo.sh ./snippet.py
```

## Basic usage

```bash
chmod +x ./audit_repo.sh
./audit_repo.sh <target> [output-dir]
```

Example:

```bash
./audit_repo.sh ./my-project ./audit-report
```

## Optional modes

```bash
RUN_BUILD=1 ./audit_repo.sh ./my-project ./audit-report
```

Runs a build and tests as part of the audit. This executes project code, so use a safe environment such as Docker or a VM.

```bash
REPORT_ONLY=1 ./audit_repo.sh ./my-project ./audit-report
```

Skips scanning and rebuilds the report from existing JSON output files.

```bash
NO_PDF=1 ./audit_repo.sh ./my-project ./audit-report
```

Writes the Markdown report and findings JSON without generating the PDF.

## What is required to use it

### Required tools

- `git`
- `python3`
- `npm` (only if Node.js-based dependency check is needed)

### Optional but recommended tools

The script checks for and uses these tools if they are installed:

- `osv-scanner`
- `trivy`
- `gitleaks`
- `semgrep`
- `reportlab` (for PDF generation)

If any optional tool is missing, the script still continues and records that fact in the report output instead of failing silently.

## Output files

When run, the script writes results into the chosen output directory, for example `./audit-report`:

- `Security_Audit_Report.pdf`
- `REPORT.md`
- `findings.json`
- raw scanner outputs
- `overview.txt`
- `tool_status.tsv`
- `meta.env`

## Severity levels

The report ranks findings as:

- Critical
- High
- Medium
- Low

This helps prioritize the most dangerous issues first.

## Important notes

This tool is automated and can produce false positives. The script itself warns that results should be reviewed carefully before acting on them.

Use it as a first-pass auditing tool, not as a final authority. Always verify important findings by reading the relevant code.

## Example command flow

```bash
chmod +x ./audit_repo.sh
./audit_repo.sh ./my-project ./audit-report
```

Then open:

- `./audit-report/REPORT.md`
- `./audit-report/Security_Audit_Report.pdf`

## Project structure

- `audit_repo.sh` — main automated audit script
- `README.md` — usage and documentation
- `audit_repo_Explained.pdf` — explanatory PDF guide

## Quick prerequisites checklist

Before running this script, make sure you have:

1. a target project to review
2. Git installed
3. Python 3 installed
4. optional scanner tools installed if you want richer results
5. sufficient permissions to read the project and generate output files

## Typical use cases

- security review of a repository
- quick vulnerability scan before deployment
- code audit of a new codebase
- PDF report generation for stakeholder review
- documentation of issues for a bug bounty or internal assessment

## Final reminder

This repository is meant to help automate code review and find likely problems early. It is not a substitute for human judgment. Always verify the top findings in context before fixing or trusting them.

---

This markdown file is a plain-English version of the original explanation PDF for the script and is intended to make the project easier to understand and use.
