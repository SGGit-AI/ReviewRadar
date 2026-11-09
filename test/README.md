# Test Cases for ReviewRadar

This folder contains validation scenarios for the repository auditing script.

## Purpose

These cases are designed to verify that the script behaves correctly across the most important real-world situations:

- repo scanning
- dependency vulnerability detection
- secret detection
- single-file mode
- missing-tool handling
- PDF generation
- false-positive checking
- large-project validation

## Included test scenarios

### 1. vulnerable-deps

A sample project with a vulnerable dependency manifest. This is used to confirm the script catches dependency issues and ranks them properly.

### 2. secret-leak

A small repository containing a fake API key, token, or private key. This verifies secret detection and redaction behavior.

### 3. benign-project

A clean project with no obvious vulnerabilities. This helps validate false-positive handling and ensure the tool is not over-reporting.

### 4. single-file-sample

A single source file that should be scanned successfully without requiring a full repo context.

### 5. missing-tool-simulated

A scenario designed to simulate optional tools being unavailable so the script can still run and report the tool status correctly.

### 6. large-repo-sample

A larger structure used to confirm the script handles bigger repositories and still writes clean output.

## How to use

Create a scenario under this folder and run:

```bash
./audit_repo.sh <path-to-test-case> ./audit-report
```

Then review the generated report and compare the findings against what you expected.

## Recommended validation checklist

For every test case, confirm:

- the script starts successfully
- the report file is created
- the findings match the target scenario
- severity levels are sensible
- tool status is recorded correctly
- false positives are clearly reviewed by a human

## Example

```bash
./audit_repo.sh ./test/secret-leak ./audit-report
```

Then open:

- `./audit-report/REPORT.md`
- `./audit-report/Security_Audit_Report.pdf`
