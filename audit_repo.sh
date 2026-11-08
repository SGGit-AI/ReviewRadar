#!/usr/bin/env bash
# =============================================================================
# audit_repo.sh  -  automated security/quality audit with a PDF report
#
# USAGE
#   ./audit_repo.sh <target> [output-dir]
#
#   <target> can be:
#     * a Git URL            https://github.com/juice-shop/juice-shop
#     * a local folder       ./my-project
#     * a single file        ./snippet.py     (snippet mode)
#
#   RUN_BUILD=1    also run "npm install/test" (executes repo code: use Docker/VM)
#   REPORT_ONLY=1  skip scanning, rebuild REPORT.md / PDF from existing JSON in output-dir
#   NO_PDF=1       write REPORT.md and findings.json only
#
# TOOLS (all optional; missing or failing tools are listed in the report, never hidden)
#   git, npm, python3 (required) | semgrep, trivy, gitleaks, osv-scanner | reportlab (for PDF)
#
# OUTPUT (in output-dir)
#   Security_Audit_Report.pdf  REPORT.md  findings.json  + raw scanner outputs
#
# NOTE: results are automated and unverified. Expect false positives; confirm each
# finding by reading the code before acting on it.
# =============================================================================
set -u

usage() { sed -n '2,24p' "$0"; exit 1; }
TARGET="${1:-}"; [[ -z "$TARGET" ]] && usage
OUT="${2:-./audit-report}"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
STATUS="$OUT/tool_status.tsv"

have() { command -v "$1" >/dev/null 2>&1; }
st()   { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$STATUS"; echo "    [$2] $1${3:+ - $3}"; }
one_line() { tr '\n\t' '  ' | cut -c1-220; }
valid_json() { python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$1" >/dev/null 2>&1; }

if ! have python3; then echo "python3 is required"; exit 1; fi

# ---- decide the mode ---------------------------------------------------------
MODE=""
if [[ "${REPORT_ONLY:-0}" != "1" ]]; then
  if   [[ -f "$TARGET" ]]; then MODE=file
  elif [[ "$TARGET" =~ ^https?:// || "$TARGET" =~ ^git@ ]]; then MODE=repo
  elif [[ -d "$TARGET" ]]; then MODE=dir
  else echo "Target not found: $TARGET"; exit 1; fi
fi

run_scans() {
  : > "$STATUS"
  local WORK IS_GIT=0 COMMIT="n/a"
  case "$MODE" in
    file) WORK="$OUT/snippet"; rm -rf "$WORK"; mkdir -p "$WORK"; cp "$TARGET" "$WORK/" ;;
    repo) WORK="$OUT/repo"
          if [[ -d "$WORK/.git" ]]; then echo "[*] Reusing clone at $WORK"
          else echo "[*] Cloning $TARGET (full history, needed for secret scanning)"
               git clone "$TARGET" "$WORK" || { echo "Clone failed"; exit 1; }; fi ;;
    dir)  WORK="$(cd "$TARGET" && pwd)" ;;
  esac
  cd "$WORK" || exit 1
  git rev-parse --is-inside-work-tree >/dev/null 2>&1 && IS_GIT=1
  [[ $IS_GIT -eq 1 ]] && COMMIT="$(git rev-parse --short HEAD 2>/dev/null)"

  { echo "target=$TARGET"; echo "mode=$MODE"; echo "commit=$COMMIT"
    echo "date=$(date -u +%Y-%m-%d)"; } > "$OUT/meta.env"

  # ---- 1. overview (repo/dir only) -------------------------------------------
  echo "[*] Overview"
  if [[ "$MODE" != "file" ]]; then
    {
      if [[ $IS_GIT -eq 1 ]]; then
        echo "Files tracked: $(git ls-files | wc -l)   Contributors: $(git shortlog -sn --all 2>/dev/null | wc -l)"
        echo "Last commit:   $(git log -1 --format=%cd 2>/dev/null)"
        echo; echo "Manifests:"
        git ls-files | grep -E '(^|/)(package\.json|requirements.*\.txt|Pipfile|pyproject\.toml|go\.mod|pom\.xml|build\.gradle|Gemfile|composer\.json|Cargo\.toml|Dockerfile|docker-compose.*\.ya?ml)$' | head -15
        echo; echo "Most-changed files (bug hotspots):"
        git log --format=format: --name-only 2>/dev/null | grep -v '^$' | sort | uniq -c | sort -rn | head -8
      else
        echo "Not a git repository: history-based checks skipped."
        find . -type f -not -path '*/node_modules/*' | wc -l | xargs echo "Files:"
      fi
    } > "$OUT/overview.txt"
  else
    echo "Single file: $(basename "$TARGET")  ($(wc -l < "$TARGET") lines)" > "$OUT/overview.txt"
  fi

  # ---- 2. temporary lockfiles (many repos gitignore theirs) -------------------
  GENERATED_LOCKS=()
  if [[ "$MODE" != "file" ]] && have npm; then
    while IFS= read -r pj; do
      d="$(dirname "$pj")"
      if [[ ! -f "$d/package-lock.json" && ! -f "$d/yarn.lock" && ! -f "$d/pnpm-lock.yaml" ]]; then
        if (cd "$d" && npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null 2>&1); then
          GENERATED_LOCKS+=("$d/package-lock.json")
        fi
      fi
    done < <(find . -name package.json -not -path '*/node_modules/*' -not -path './.git/*' | head -10)
    [[ ${#GENERATED_LOCKS[@]} -gt 0 ]] && echo "[*] Generated ${#GENERATED_LOCKS[@]} temporary lockfile(s) (removed at the end)"
  fi

  # ---- 3. dependency scanners -------------------------------------------------
  echo "[*] Dependency scanners"
  if [[ "$MODE" == "file" ]]; then
    st "osv-scanner" "n/a" "single file has no dependency manifest"
    st "npm audit" "n/a" "single file has no dependency manifest"
  else
    if have osv-scanner; then
      osv-scanner scan source --no-ignore -r . --format json --output "$OUT/osv.json" >"$OUT/osv.log" 2>&1
      osv-scanner scan source --no-ignore -r . > "$OUT/osv.txt" 2>&1
      if grep -qi "No package sources found" "$OUT/osv.txt"; then st "osv-scanner" "failed" "no lockfiles found, result is NOT clean"
      elif grep -qiE "Error during extraction|request failed|no such host" "$OUT/osv.txt"; then st "osv-scanner" "failed" "could not reach api.osv.dev, result is NOT clean"
      else st "osv-scanner" "ok" ""; fi
    else st "osv-scanner" "skipped" "not installed (https://google.github.io/osv-scanner/)"; fi

    if have npm; then
      n=0
      while IFS= read -r lock; do
        d="$(dirname "$lock")"; tag="$(echo "$d" | tr '/.' '__')"
        (cd "$d" && npm audit --json > "$OUT/npm-audit$tag.json" 2>/dev/null)
        valid_json "$OUT/npm-audit$tag.json" && n=$((n+1))
      done < <(find . -name package-lock.json -not -path '*/node_modules/*' -not -path './.git/*' | head -10)
      if [[ $n -gt 0 ]]; then st "npm audit" "ok" "$n lockfile(s)"; else st "npm audit" "n/a" "no Node.js lockfile"; fi
    else st "npm audit" "skipped" "npm not installed"; fi
  fi

  # ---- 4. trivy (dependencies, secrets, misconfiguration) ---------------------
  echo "[*] Trivy"
  if have trivy; then
    trivy fs . --scanners vuln,secret,misconfig --severity CRITICAL,HIGH,MEDIUM,LOW \
          --format json --output "$OUT/trivy.json" > "$OUT/trivy.log" 2>&1
    if grep -q "FATAL" "$OUT/trivy.log" || ! valid_json "$OUT/trivy.json"; then
      st "trivy" "failed" "$(grep -m1 FATAL "$OUT/trivy.log" | one_line)"; rm -f "$OUT/trivy.json"
    else st "trivy" "ok" ""; fi
  else st "trivy" "skipped" "not installed (https://trivy.dev)"; fi

  # ---- 5. secrets (values redacted) -------------------------------------------
  echo "[*] Gitleaks"
  if have gitleaks; then
    GL=(detect --source . --report-format json --report-path "$OUT/gitleaks.json" --redact --no-banner)
    [[ $IS_GIT -eq 0 ]] && GL+=(--no-git)
    gitleaks "${GL[@]}" > "$OUT/gitleaks.log" 2>&1; rc=$?
    if [[ $rc -le 1 ]] && valid_json "$OUT/gitleaks.json"; then
      st "gitleaks" "ok" "$([[ $IS_GIT -eq 1 ]] && echo 'incl. git history' || echo 'files only')"
    else st "gitleaks" "failed" "$(tail -1 "$OUT/gitleaks.log" | one_line)"; fi
  else st "gitleaks" "skipped" "not installed (https://github.com/gitleaks/gitleaks)"; fi

  # ---- 6. static analysis -----------------------------------------------------
  echo "[*] Semgrep"
  if have semgrep; then
    # '--config auto' forces metrics ON, so explicit rule packs are used instead.
    semgrep scan --config p/security-audit --config p/owasp-top-ten --metrics=off \
      --exclude node_modules --exclude test --exclude '*.min.js' \
      --json -o "$OUT/semgrep.json" . > "$OUT/semgrep.log" 2>&1
    if valid_json "$OUT/semgrep.json"; then st "semgrep" "ok" ""
    else st "semgrep" "failed" "needs internet for rule packs: $(tail -1 "$OUT/semgrep.log" | one_line)"; rm -f "$OUT/semgrep.json"; fi
  else st "semgrep" "skipped" "not installed (pip install semgrep)"; fi

  # ---- 7. build + tests (opt-in) ----------------------------------------------
  echo "[*] Build and tests"
  if [[ "${RUN_BUILD:-0}" == "1" && "$MODE" != "file" ]]; then
    if [[ -f package.json ]] && have npm; then
      npm install --ignore-scripts > "$OUT/build.log" 2>&1; b=$?
      timeout 600 npm test > "$OUT/test.log" 2>&1; t=$?
      st "build/test" "ok" "npm install exit=$b, npm test exit=$t (see build.log, test.log)"
    else st "build/test" "n/a" "only Node.js projects are auto-detected"; fi
  else st "build/test" "skipped" "opt-in: RUN_BUILD=1 (executes repo code, use Docker/VM)"; fi

  for f in "${GENERATED_LOCKS[@]:-}"; do [[ -n "$f" ]] && rm -f "$f"; done
}

if [[ "${REPORT_ONLY:-0}" != "1" ]]; then run_scans; fi

# =============================================================================
# Report builder: merges all scanner outputs into one ranked, de-duplicated list
# =============================================================================
echo "[*] Building report"
NO_PDF="${NO_PDF:-0}" python3 - "$OUT" <<'__PYREPORT__'
import sys, os, json, re, glob, collections

OUT = sys.argv[1]
ORDER = ["Critical", "High", "Medium", "Low"]

def load(p):
    try: return json.load(open(p))
    except Exception: return None

def readkv(p):
    m = {}
    if os.path.exists(p):
        for l in open(p):
            if "=" in l:
                k, v = l.rstrip("\n").split("=", 1); m[k] = v
    return m

META = readkv(os.path.join(OUT, "meta.env"))
TOOLS = []
p = os.path.join(OUT, "tool_status.tsv")
if os.path.exists(p):
    for l in open(p):
        a = l.rstrip("\n").split("\t")
        if len(a) >= 3: TOOLS.append(a[:3])
OVERVIEW = open(os.path.join(OUT, "overview.txt")).read() if os.path.exists(os.path.join(OUT, "overview.txt")) else ""

def nsev(s):
    return {"critical": "Critical", "high": "High", "error": "High", "moderate": "Medium", "medium": "Medium",
            "warning": "Medium", "unknown": "Medium", "low": "Low", "info": "Low", "note": "Low"}.get(str(s or "").strip().lower(), "Medium")
def score_sev(x):
    try: x = float(x)
    except Exception: return None
    return "Critical" if x >= 9 else "High" if x >= 7 else "Medium" if x >= 4 else "Low"
def worse(a, b): return a if ORDER.index(a) <= ORDER.index(b) else b

# ---------- remediation knowledge base (first match wins) ----------------------
FIXES = [
 (r"sql.?inject|sqli|\bsql\b.*(concat|format|string)|tainted.?sql", "Use parameterized queries / bound parameters (ORM replacements). Never build SQL by concatenating user input."),
 (r"command.?inject|os.?command|shell.?inject|child.?process|\bexec\b|subprocess|spawn", "Avoid the shell. Use execFile/subprocess with an argument list, validate input against an allow-list."),
 (r"\bxss\b|cross.?site.?script|innerhtml|dangerouslysetinnerhtml|unescaped|raw.?html", "Encode output for its context, avoid innerHTML-style sinks, sanitize with a maintained library, and add a Content-Security-Policy."),
 (r"path.?traversal|directory.?traversal|zip.?slip|arbitrary file|symlink|hardlink|file overwrite|outside of the target", "Resolve the final path and verify it stays inside the intended base directory. Reject '..' and absolute paths in archive entries. Upgrade the library."),
 (r"prototype.?pollution", "Upgrade the library. Do not merge untrusted objects into plain objects (use Object.create(null) or schema validation)."),
 (r"redos|regular expression denial|catastrophic|backtracking", "Upgrade to a patched version. Cap input length and avoid nested quantifiers in custom regexes."),
 (r"denial.?of.?service|\bdos\b|infinite loop|resource exhaustion", "Upgrade to a patched version. Add request size limits, timeouts and rate limiting."),
 (r"ssrf|server.?side request", "Allow-list destination hosts, resolve and block private/internal IP ranges, disable redirects for server-side fetches."),
 (r"open.?redirect|unvalidated redirect|redirect", "Parse the URL and compare its exact origin against an allow-list. Never use substring checks."),
 (r"md5|sha-?1\b|weak.?hash|weak.?crypto|insecure.?hash|des\b|ecb", "Passwords: argon2id or bcrypt with per-user salt. Integrity: SHA-256 or better. Encryption: AES-GCM. Migrate old hashes at next login."),
 (r"private.?key|hard.?coded|api.?key|secret|credential|generic-api-key", "Treat the value as compromised: rotate it, remove it from code, load from environment or a secret manager, and purge it from git history (git filter-repo/BFG)."),
 (r"pbkdf2|entropy|random|insecure random", "Use a cryptographically secure RNG (crypto.randomBytes / secrets module) and current key-derivation parameters."),
 (r"cors|cross.?origin", "Restrict allowed origins to an explicit allow-list; never reflect arbitrary origins, especially with credentials."),
 (r"csrf|cross.?site request", "Add CSRF tokens and SameSite cookies on state-changing requests."),
 (r"deserial|pickle|yaml\.load|unsafe.?load", "Do not deserialize untrusted data. Use safe formats (JSON) or safe loaders."),
 (r"verification bypass|authorization bypass|authentication|forgeable|forge|hmac signature|jwt|algorithm", "Upgrade the auth library, pin accepted algorithms explicitly, verify signature, expiry, issuer and audience."),
 (r"eval|code.?inject|sandbox escape|vm2|new function", "Remove eval/dynamic code execution on untrusted input; use a real parser or a hardened isolate."),
 (r"tls|ssl|certificate|verify=false|rejectunauthorized", "Enable certificate verification and use modern TLS versions."),
 (r"docker|root user|privileged|latest tag|user.?root|runasnonroot|healthcheck", "Run as a non-root user, pin image versions, use minimal base images, drop capabilities."),
 (r"sensitive information|information exposure|exposure of sensitive|information disclosure|stack trace|debug", "Return generic errors, disable debug output in production, and keep sensitive files out of served directories."),
]
DEFAULT_FIX = "Review the finding, apply the vendor/advisory remediation, or upgrade to a patched version."
def fix_for(*texts):
    t = " ".join(x for x in texts if x).lower()
    for rx, msg in FIXES:
        if re.search(rx, t): return msg
    return DEFAULT_FIX

# ---------- collection -----------------------------------------------------------
F = []          # non-dependency findings
DEPS = {}       # package -> merged record
NOTES = []      # parser problems (shown in report)

def add(kind, sev, src, title, loc, fix):
    F.append(dict(kind=kind, sev=sev, src=src, title=title[:230], loc=loc[:140], fix=fix))

def dep(name, sev, src, title, ids=(), fix=None, direct=None, ver=None, rng=None):
    d = DEPS.setdefault(name, dict(sev=sev, sources=[], titles=[], ids=set(), fixes=[], direct=None, ver=None, rng=None))
    d["sev"] = worse(d["sev"], sev)
    if src not in d["sources"]: d["sources"].append(src)
    if title and title not in d["titles"]: d["titles"].append(title)
    d["ids"].update(ids)
    if fix and fix not in d["fixes"]: d["fixes"].append(fix)
    if direct is not None: d["direct"] = bool(direct) if d["direct"] is None else (d["direct"] or bool(direct))
    d["ver"] = d["ver"] or ver; d["rng"] = d["rng"] or rng

# npm audit -------------------------------------------------------------------------
for f in glob.glob(os.path.join(OUT, "npm-audit*.json")):
    try:
        d = load(f); vs = (d or {}).get("vulnerabilities")
        if not vs: continue
        openset = {n for n, v in vs.items() if ">=" in v.get("range", "")}   # no patched release
        for n, x in vs.items():
            adv = [y for y in x.get("via", []) if isinstance(y, dict)]
            chain = [y for y in x.get("via", []) if isinstance(y, str)]
            title = adv[0].get("title", "") if adv else ("Inherited via " + ", ".join(chain[:3]) if chain else "Known vulnerability")
            if len(adv) > 1: title += f" (+{len(adv)-1} more advisories)"
            ids = [m.group(0) for y in adv for m in [re.search(r"GHSA-[\w-]+", y.get("url", ""))] if m]
            fa = x.get("fixAvailable")
            if isinstance(fa, dict) and ">=" in x.get("range", ""):
                fix = f"No patched release. npm suggests {fa['name']}@{fa['version']} which is older or still affected: replace the package or pin and review."
            elif isinstance(fa, dict) and fa["name"] in openset and fa["name"] != n:
                fix = f"Use an npm 'overrides' entry to pin a patched {n}. npm's suggested route ({fa['name']}@{fa['version']}) does not truly resolve it."
            elif isinstance(fa, dict):
                fix = f"Upgrade {fa['name']} to {fa['version']}" + (" (major version: run tests)." if fa.get("isSemVerMajor") else ".")
            elif fa is True: fix = "Run 'npm audit fix'."
            else: fix = "No fix available: replace or remove this package."
            dep(n, nsev(x.get("severity")), "npm audit", title, ids, fix, x.get("isDirect"), None, x.get("range"))
    except Exception as e: NOTES.append(f"npm audit parse error ({os.path.basename(f)}): {e}")

# OSV-Scanner -----------------------------------------------------------------------
try:
    d = load(os.path.join(OUT, "osv.json"))
    for res in (d or {}).get("results", []):
        for pkg in res.get("packages", []):
            p = pkg.get("package", {}); name = p.get("name") or "unknown"
            gmax = {}
            for g in pkg.get("groups", []):
                for i in g.get("ids", []): gmax[i] = g.get("max_severity")
            for v in pkg.get("vulnerabilities", []):
                lab = (v.get("database_specific") or {}).get("severity")
                sev = nsev(lab) if lab else (score_sev(gmax.get(v.get("id"))) or "Medium")
                fixed = sorted({e["fixed"] for a in v.get("affected", []) for r in a.get("ranges", []) for e in r.get("events", []) if "fixed" in e})
                fix = (f"Upgrade {name} to " + " or ".join(fixed[:3]) + " (or later).") if fixed else None
                ids = [v.get("id", "")] + [a for a in v.get("aliases", []) if a.startswith("GHSA")]
                dep(name, sev, "OSV", v.get("summary") or v.get("id", "vulnerability"), [i for i in ids if i], fix, None, p.get("version"))
except Exception as e: NOTES.append(f"OSV parse error: {e}")

# Trivy -----------------------------------------------------------------------------
try:
    d = load(os.path.join(OUT, "trivy.json"))
    for r in (d or {}).get("Results", []) or []:
        tgt = r.get("Target", "")
        for v in r.get("Vulnerabilities") or []:
            fx = v.get("FixedVersion")
            dep(v.get("PkgName", "unknown"), nsev(v.get("Severity")), "Trivy", v.get("Title") or v.get("VulnerabilityID", ""),
                [v.get("VulnerabilityID", "")], (f"Upgrade {v.get('PkgName','package')} to " + fx + " (or later).") if fx else None, None, v.get("InstalledVersion"))
        for s in r.get("Secrets") or []:
            add("Secrets", nsev(s.get("Severity")), "Trivy", s.get("Title") or s.get("RuleID", "Secret"), f"{tgt}:{s.get('StartLine','?')}",
                fix_for("secret", s.get("RuleID"), s.get("Title")))
        for m in r.get("Misconfigurations") or []:
            line = (m.get("CauseMetadata") or {}).get("StartLine")
            add("Config", nsev(m.get("Severity")), "Trivy", (m.get("ID", "") + " " + (m.get("Title") or "")).strip(),
                f"{tgt}" + (f":{line}" if line else ""), (m.get("Resolution") or fix_for(m.get("Title"), m.get("Message")))[:260])
except Exception as e: NOTES.append(f"Trivy parse error: {e}")

# Gitleaks (values are redacted by the script) ---------------------------------------
try:
    d = load(os.path.join(OUT, "gitleaks.json")) or []
    noise = re.compile(r'(^|/)(tests?|__tests__|spec|e2e|cypress|fixtures?|mocks?|examples?|samples?|docs?)(/|$)|\.(test|spec)\.|\.md$', re.I)
    real = [x for x in d if not noise.search(x.get("File", ""))]
    groups = collections.OrderedDict()
    for x in real: groups.setdefault((x.get("File"), x.get("RuleID", "secret")), []).append(x)
    for (fname, rule), xs in groups.items():
        sev = "Critical" if "private-key" in rule else ("Medium" if rule == "generic-api-key" else "High")
        loc = f"{fname}:{xs[0].get('StartLine')}" + (f" (+{len(xs)-1} more in git history)" if len(xs) > 1 else "")
        add("Secrets", sev, "Gitleaks", f"Possible secret ({rule})", loc, fix_for("secret", rule))
    if len(d) - len(real) > 0:
        add("Secrets", "Low", "Gitleaks", f"{len(d)-len(real)} possible secrets in test/fixture/doc paths", "test, docs, fixtures",
            "Usually fake data. Spot-check a few; if any is real, treat as compromised and rotate.")
except Exception as e: NOTES.append(f"Gitleaks parse error: {e}")

# Semgrep ---------------------------------------------------------------------------
try:
    d = load(os.path.join(OUT, "semgrep.json")); seen = set()
    for r in (d or {}).get("results", []):
        ex = r.get("extra", {}); md = ex.get("metadata") or {}
        cwe = md.get("cwe"); cwe = ", ".join(cwe) if isinstance(cwe, list) else (cwe or "")
        cid = r.get("check_id", "").split(".")[-1]
        key = (cid, r.get("path"), r.get("start", {}).get("line"))
        if key in seen: continue
        seen.add(key)
        title = cid.replace("-", " ").replace("_", " ")
        if cwe: title += f" [{cwe.split(':')[0]}]"
        fx = ex.get("fix")
        fix = fix_for(cid, ex.get("message"), cwe)
        if fx: fix = "Suggested patch: " + str(fx)[:160] + ". " + fix
        add("Code", nsev(ex.get("severity")), "Semgrep", title, f"{r.get('path')}:{r.get('start', {}).get('line')}", fix)
except Exception as e: NOTES.append(f"Semgrep parse error: {e}")

# ---------- merge into one list ---------------------------------------------------
ITEMS = list(F)
for name, d in DEPS.items():
    t = d["titles"][0] if d["titles"] else "Known vulnerability"
    if len(d["titles"]) > 1 and "more advisories" not in t: t += f" (+{len(d['titles'])-1} more)"
    ver = d["ver"] or d["rng"] or ""
    loc = f"{name} {ver}".strip() + (" (direct)" if d["direct"] else "")
    fixes = sorted(d["fixes"], key=lambda f: 0 if f.startswith(f"Upgrade {name} to") else 1)[:2]
    ITEMS.append(dict(kind="Dependencies", sev=d["sev"], src=", ".join(d["sources"]), title=t[:230], loc=loc[:140],
                      fix=" / ".join(fixes)[:300] if fixes else "Upgrade to a patched release; if none exists, replace the package."))
KIND_ORDER = {"Secrets": 0, "Code": 1, "Config": 2, "Dependencies": 3}
ITEMS.sort(key=lambda i: (ORDER.index(i["sev"]), KIND_ORDER[i["kind"]], i["loc"]))
cnt = collections.Counter()
for i in ITEMS:
    cnt[i["sev"]] += 1; i["id"] = f"{i['sev'][0]}-{cnt[i['sev']]:02d}"
json.dump(ITEMS, open(os.path.join(OUT, "findings.json"), "w"), indent=2)
matrix = {k: collections.Counter(i["sev"] for i in ITEMS if i["kind"] == k) for k in KIND_ORDER}
TOTAL = collections.Counter(i["sev"] for i in ITEMS)
failed = [t for t in TOOLS if t[1] in ("failed",)]
skipped = [t for t in TOOLS if t[1] == "skipped"]

# ---------- Markdown report -------------------------------------------------------
md = [f"# Security audit report", f"- Target: {META.get('target','?')}  (mode: {META.get('mode','?')})",
      f"- Commit: {META.get('commit','n/a')}   Date: {META.get('date','?')}", "",
      "## Summary", "", "| Category | Critical | High | Medium | Low |", "|---|---|---|---|---|"]
for k, c in matrix.items(): md.append(f"| {k} | " + " | ".join(str(c.get(s, 0)) for s in ORDER) + " |")
md.append("| **Total** | " + " | ".join(f"**{TOTAL.get(s,0)}**" for s in ORDER) + " |")
md += ["", "## Tool status", "", "| Tool | Status | Notes |", "|---|---|---|"] + [f"| {a} | {b} | {c} |" for a, b, c in TOOLS]
if failed or skipped:
    md += ["", "**Warning: some tools did not run, so the counts above are a lower bound, not a clean bill of health.**"]
for n in NOTES: md.append(f"- {n}")
for s in ORDER:
    rows = [i for i in ITEMS if i["sev"] == s]
    if not rows: continue
    md += ["", f"## {s} ({len(rows)})", "", "| ID | Source | Finding | Location | How to fix |", "|---|---|---|---|---|"]
    for i in rows:
        md.append("| " + " | ".join(x.replace("|", "/") for x in (i["id"], i["src"], i["title"], i["loc"], i["fix"])) + " |")
open(os.path.join(OUT, "REPORT.md"), "w").write("\n".join(md) + "\n")
print(f"    REPORT.md, findings.json written ({len(ITEMS)} findings: " + ", ".join(f"{s}={TOTAL.get(s,0)}" for s in ORDER) + ")")

# ---------- PDF -------------------------------------------------------------------
if os.environ.get("NO_PDF") == "1": sys.exit(0)
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table, TableStyle, PageBreak, XPreformatted, KeepTogether
except ImportError:
    print("    PDF skipped: reportlab not installed (pip install reportlab, in a venv if pip complains)"); sys.exit(0)

SEV = {"Critical": colors.HexColor("#B71C1C"), "High": colors.HexColor("#E65100"), "Medium": colors.HexColor("#B8860B"), "Low": colors.HexColor("#546E7A")}
BG = {"Critical": colors.HexColor("#FDECEA"), "High": colors.HexColor("#FFF3E0"), "Medium": colors.HexColor("#FFF8E1"), "Low": colors.HexColor("#ECEFF1")}
INK = colors.HexColor("#1F2933"); MUTED = colors.HexColor("#616E7C"); RULE = colors.HexColor("#D9DEE3"); NAVY = colors.HexColor("#14263F"); CODEBG = colors.HexColor("#F4F6F8")
def S(n, **k):
    b = dict(fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK); b.update(k); return ParagraphStyle(n, **b)
body = S("b"); cell = S("c", fontSize=7.8, leading=9.8); cellb = S("cb", fontName="Helvetica-Bold", fontSize=7.8, leading=9.8)
h1 = S("h1", fontName="Helvetica-Bold", fontSize=16, leading=20, textColor=NAVY, spaceBefore=4, spaceAfter=8)
def esc(t): return str(t).encode("latin-1", "replace").decode("latin-1").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
def P(t, st=cell): return Paragraph(esc(t), st)

PDF = os.path.join(OUT, "Security_Audit_Report.pdf")
def foot(c, doc):
    c.saveState(); c.setFont("Helvetica", 7.5); c.setFillColor(MUTED)
    c.drawString(0.75*inch, 0.5*inch, f"Security audit | {META.get('target','')[:70]} | {META.get('date','')}")
    c.drawRightString(7.75*inch, 0.5*inch, f"Page {doc.page}")
    c.setStrokeColor(RULE); c.line(0.75*inch, 0.65*inch, 7.75*inch, 0.65*inch); c.restoreState()
doc = BaseDocTemplate(PDF, pagesize=letter, leftMargin=0.75*inch, rightMargin=0.75*inch, topMargin=0.7*inch, bottomMargin=0.85*inch, title="Security audit report")
doc.addPageTemplates([PageTemplate(id="p", frames=[Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height)], onPage=foot)])
st = []

band = Table([[Paragraph("<font color='white'><b>SECURITY AUDIT REPORT</b></font>", S("x", fontSize=9, textColor=colors.white))],
              [Paragraph("<font color='white'><b>" + esc(os.path.basename(META.get('target', '').rstrip('/')) or 'Target') + "</b></font>", S("y", fontSize=22, leading=26, textColor=colors.white))],
              [Paragraph("<font color='#C9D3E0'>" + esc(f"{META.get('target','')}  |  mode: {META.get('mode','')}  |  commit {META.get('commit','n/a')}  |  {META.get('date','')}") + "</font>", S("z", fontSize=8.5, textColor=colors.white))]], colWidths=[7.0*inch])
band.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), NAVY), ("LEFTPADDING", (0,0), (-1,-1), 16), ("TOPPADDING", (0,0), (-1,0), 14), ("BOTTOMPADDING", (0,-1), (-1,-1), 14)]))
st += [band, Spacer(1, 10)]
warn = "Automated results. Findings come straight from scanners and are <b>not manually verified</b>; expect false positives, especially in code and secrets. Confirm each item by reading the code before acting."
if failed or skipped:
    warn += " <b>Some tools did not run (see Tool status), so these counts are a lower bound and not evidence of safety.</b>"
st.append(Paragraph(warn, S("w", fontSize=8.8, leading=12.5, backColor=BG["Medium"], borderPadding=6, borderColor=SEV["Medium"], borderWidth=0.6)))
st += [Spacer(1, 12), Paragraph("1. Summary", h1)]

def num(n, s): return Paragraph(f"<font color='{SEV[s].hexval().replace('0x','#')}' size='14'><b>{n}</b></font>", S("n", alignment=1, leading=17))
hdr = [P("Category", cellb)] + [Paragraph(f"<font color='white'><b>{s}</b></font>", S("hh", fontSize=8.5, alignment=1, textColor=colors.white)) for s in ORDER]
rows = [hdr] + [[P(k, cellb)] + [num(c.get(s, 0), s) for s in ORDER] for k, c in matrix.items()]
rows.append([P("Total", cellb)] + [num(TOTAL.get(s, 0), s) for s in ORDER])
t = Table(rows, colWidths=[2.4*inch] + [1.15*inch]*4, rowHeights=[0.28*inch] + [0.42*inch]*(len(rows)-1))
ts = TableStyle([("VALIGN", (0,0), (-1,-1), "MIDDLE"), ("LINEBELOW", (0,1), (-1,-1), 0.4, RULE), ("BOX", (0,0), (-1,-1), 0.5, RULE), ("BACKGROUND", (0,0), (0,0), CODEBG),
                 ("BACKGROUND", (0,-1), (-1,-1), CODEBG)])
for i, s in enumerate(ORDER): ts.add("BACKGROUND", (i+1, 0), (i+1, 0), SEV[s])
t.setStyle(ts); st += [t, Spacer(1, 12)]

st.append(Paragraph("2. Tool status", h1))
sc = {"ok": "#2E7D32", "failed": "#B71C1C", "skipped": "#B8860B", "n/a": "#616E7C"}
tr = [[P("Tool", cellb), P("Status", cellb), P("Notes", cellb)]] + [[P(a), Paragraph(f"<font color='{sc.get(b,'#000000')}'><b>{esc(b)}</b></font>", cell), P(c)] for a, b, c in TOOLS]
t = Table(tr, colWidths=[1.2*inch, 0.8*inch, 5.0*inch], repeatRows=1)
t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), CODEBG), ("LINEBELOW", (0,0), (-1,-1), 0.3, RULE), ("VALIGN", (0,0), (-1,-1), "TOP")]))
st.append(t)
for n in NOTES: st.append(Paragraph(esc(n), S("nn", fontSize=8, textColor=SEV["Critical"])))
if OVERVIEW.strip():
    ovh = Paragraph("Overview", S("oh", fontName="Helvetica-Bold", fontSize=10.5, textColor=NAVY, spaceAfter=3))
    ov = Table([[XPreformatted(esc("\n".join(OVERVIEW.splitlines()[:26])), ParagraphStyle("o", fontName="Courier", fontSize=7.2, leading=9))]], colWidths=[7.0*inch])
    ov.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), CODEBG), ("BOX", (0,0), (-1,-1), 0.5, RULE), ("LEFTPADDING", (0,0), (-1,-1), 6)]))
    st += [Spacer(1, 10), KeepTogether([ovh, ov])]
st.append(PageBreak())

st.append(Paragraph("3. Findings and how to fix them", h1))
CAP = 80
for s in ORDER:
    rows = [i for i in ITEMS if i["sev"] == s]
    if not rows: continue
    st.append(Paragraph(f"<font color='{SEV[s].hexval().replace('0x','#')}'><b>{s}</b></font> ({len(rows)})", S("sh", fontName="Helvetica-Bold", fontSize=12, leading=16, spaceBefore=8, spaceAfter=4)))
    tr = [[P("ID", cellb), P("Source", cellb), P("Finding", cellb), P("Location", cellb), P("How to fix", cellb)]]
    for i in rows[:CAP]:
        tr.append([P(i["id"], cellb), P(i["src"]), P(i["title"]), P(i["loc"]), P(i["fix"])])
    t = Table(tr, colWidths=[0.5*inch, 0.7*inch, 2.0*inch, 1.5*inch, 2.3*inch], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), BG[s]), ("LINEBELOW", (0,0), (-1,-1), 0.3, RULE), ("VALIGN", (0,0), (-1,-1), "TOP"),
                           ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3), ("LEFTPADDING", (0,0), (-1,-1), 3), ("RIGHTPADDING", (0,0), (-1,-1), 3)]))
    st.append(t)
    if len(rows) > CAP: st.append(Paragraph(esc(f"...and {len(rows)-CAP} more {s} findings in findings.json / REPORT.md"), S("m", fontSize=8, textColor=MUTED)))

st += [Spacer(1, 12), Paragraph("4. Recommended order of work", h1)]
steps = ["Secrets first: rotate anything flagged as a real key, remove it from code, purge it from git history.",
         "Injection and code-execution findings (SQL, command, XSS, eval): fix at the source with parameterized queries, encoding and allow-lists.",
         "Critical and High dependencies: run the safe upgrades, then handle breaking upgrades one at a time with tests. Replace packages that have no fix.",
         "Medium findings: hardening (CORS, headers, crypto parameters, redirects).",
         "Prevent regressions: commit lockfiles, enable Dependabot/Renovate, and run gitleaks, semgrep and trivy in CI.",
         "Verify: re-run this audit, then confirm important findings dynamically (tests or a running instance)."]
for n, x in enumerate(steps, 1): st.append(Paragraph(f"<b>{n}.</b> {esc(x)}", S("st", spaceAfter=3)))
doc.build(st)
print(f"    PDF written: {PDF}")
__PYREPORT__

echo
echo "[+] Done. Output directory: $OUT"
ls "$OUT" | grep -E "^(Security_Audit_Report.pdf|REPORT.md|findings.json)$" | sed 's/^/    /'
