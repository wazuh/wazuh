#!/bin/bash
###############################################################################
# generate_report.sh — Generate Markdown summary from CodeChecker diff results.
#
# Reads the JSON/text output produced by run_comparison.sh and produces a
# structured Markdown file compatible with GitHub issue comments.  The format
# mirrors the Coverity weekly report so reviewers see a consistent layout.
#
# Usage:
#   ./generate_report.sh \
#       --results   <results_dir>     \   # path containing diff_new.json/, summary_target.txt, …
#       --scan-ref  <base_ref>        \   # e.g. 4.14.7
#       --target-ref <target_ref>     \   # e.g. main  / fix/37131-ebpf-toctou
#       [--target   server|agent|manager] \   # default: server
#       [--output   <out.md>]             # default: <results_dir>/report.md
#
# Required inputs in <results_dir>:
#   diff_new.json/reports.json        new findings (CodeChecker cmd diff --new -o json)
#   diff_resolved.json/reports.json   fixed findings (cmd diff --resolved -o json)
#   diff_resolved.txt                 text fallback when diff_resolved.json is absent
#   summary_target.txt                contains "Number of analyzer reports | N"
###############################################################################
set -euo pipefail

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
RESULTS_DIR=""
SCAN_REF=""
TARGET_REF=""
TARGET="server"
OUTPUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --results)    RESULTS_DIR="$2"; shift 2 ;;
        --scan-ref)   SCAN_REF="$2";   shift 2 ;;
        --target-ref) TARGET_REF="$2"; shift 2 ;;
        --target)     TARGET="$2";     shift 2 ;;
        --output)     OUTPUT="$2";     shift 2 ;;
        --help|-h)
            grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -20
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

[ -n "$RESULTS_DIR" ]  || { echo "error: --results required"; exit 1; }
[ -n "$SCAN_REF" ]     || { echo "error: --scan-ref required"; exit 1; }
[ -n "$TARGET_REF" ]   || { echo "error: --target-ref required"; exit 1; }

RESULTS_DIR="${RESULTS_DIR%/}"
OUTPUT="${OUTPUT:-$RESULTS_DIR/report.md}"

NEW_JSON="$RESULTS_DIR/diff_new.json/reports.json"
RESOLVED_JSON="$RESULTS_DIR/diff_resolved.json/reports.json"
RESOLVED_TXT="$RESULTS_DIR/diff_resolved.txt"
SUMMARY_TXT="$RESULTS_DIR/summary_target.txt"

CC_VERSION="$(CodeChecker version 2>/dev/null | grep -oP '(?<=Base package version: )\S+' || echo "unknown")"

# ---------------------------------------------------------------------------
# Helper: Python3 generates the Markdown body (no jq dependency)
# ---------------------------------------------------------------------------
python3 - \
    "$NEW_JSON" \
    "${RESOLVED_JSON}" \
    "${RESOLVED_TXT}" \
    "${SUMMARY_TXT}" \
    "$SCAN_REF" \
    "$TARGET_REF" \
    "$TARGET" \
    "$OUTPUT" \
    "$CC_VERSION" \
<< 'PYEOF'
import json, os, re, sys
from datetime import datetime, timezone

new_json_path     = sys.argv[1]
resolved_json     = sys.argv[2]
resolved_txt      = sys.argv[3]
summary_txt       = sys.argv[4]
scan_ref          = sys.argv[5]
target_ref        = sys.argv[6]
target            = sys.argv[7]
output_path       = sys.argv[8]
cc_version        = sys.argv[9] if len(sys.argv) > 9 else "unknown"

# ── severity → impact label ────────────────────────────────────────────────
SEV_LABEL = {
    "critical":    "CRITICAL",
    "high":        "HIGH",
    "medium":      "MEDIUM",
    "low":         "LOW",
    "style":       "STYLE",
    "unspecified": "UNSPECIFIED",
}

# ── review_status → emoji ──────────────────────────────────────────────────
STATUS_EMOJI = {
    "unreviewed":      "🟡",
    "confirmed":       "🔴",
    "false_positive":  "⚪",
    "intentional":     "🟢",
    "suppress":        "🔵",
}

def file_path(report):
    """Extract the source file path from a report dict."""
    f = report.get("file", "")
    if isinstance(f, dict):
        return f.get("path") or f.get("original_path") or f.get("id") or ""
    return str(f)

def short_path(full_path):
    """Strip /workspace/wazuh/src/ prefix for readability."""
    for prefix in ("/workspace/wazuh/src/", "/workspace/wazuh/"):
        if full_path.startswith(prefix):
            return full_path[len(prefix):]
    return full_path

def short_hash(h):
    return h[:8] if h else "—"

# ── Load new findings (JSON) ───────────────────────────────────────────────
new_reports = []
if os.path.isfile(new_json_path):
    try:
        data = json.load(open(new_json_path))
        new_reports = data.get("reports", []) if isinstance(data, dict) else []
    except Exception as e:
        print(f"warn: could not parse {new_json_path}: {e}", file=sys.stderr)

# ── Load resolved findings (JSON preferred, text fallback) ─────────────────
resolved_reports = []

if os.path.isfile(resolved_json):
    try:
        data = json.load(open(resolved_json))
        resolved_reports = data.get("reports", []) if isinstance(data, dict) else []
    except Exception as e:
        print(f"warn: could not parse {resolved_json}: {e}", file=sys.stderr)

if not resolved_reports and os.path.isfile(resolved_txt):
    # Parse lines: [SEVERITY] /path/to/file.c:line:col: message [checker-name]
    pat = re.compile(r'^\[([A-Z]+)\]\s+(.+):(\d+):(\d+):\s+(.+?)\s+\[([^\]]+)\]')
    with open(resolved_txt) as fh:
        for line in fh:
            m = pat.match(line.strip())
            if not m:
                continue
            sev, fpath, ln, col, msg, checker = m.groups()
            resolved_reports.append({
                "severity": sev.lower(),
                "file": fpath,
                "line": int(ln),
                "column": int(col),
                "message": msg,
                "checker_name": checker,
                "report_hash": "",
                "analyzer_name": "clangsa",
                "review_status": "unreviewed",
            })

# ── Extract total count from summary_target.txt ────────────────────────────
total_count = 0
if os.path.isfile(summary_txt):
    with open(summary_txt) as fh:
        for line in fh:
            m = re.search(r'Number of analyzer reports\s*\|\s*(\d+)', line)
            if m:
                total_count = int(m.group(1))
                break

# ── Run name & version ─────────────────────────────────────────────────────
run_id = f"wazuh-{target_ref}-{target}"
platform = "Ubuntu 24.04"
report_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

# ── Build Markdown ─────────────────────────────────────────────────────────
lines = []

lines.append("## Summary\n")
lines.append("| Run ID | CodeChecker version | Platform | Total detected | Newly detected | Newly eliminated |")
lines.append("|---|---|---|---|---|---|")
lines.append(
    f"| `{run_id}` | **{cc_version}** | {platform} "
    f"| {total_count} | {len(new_reports)} | {len(resolved_reports)} |"
)
lines.append("")

lines.append("## Results\n")

# ── New defects ────────────────────────────────────────────────────────────
lines.append("<details open><summary><b>New defects:</b></summary>\n")
if new_reports:
    lines.append("| Status | Bug Hash | Type | Severity | Date | Analyzer | File |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in new_reports:
        status   = STATUS_EMOJI.get(r.get("review_status", "unreviewed"), "🟡")
        h        = short_hash(r.get("report_hash", ""))
        checker  = r.get("checker_name", "—")
        sev      = SEV_LABEL.get(r.get("severity", "").lower(), r.get("severity", "—"))
        det      = r.get("detected_at") or report_date
        if "T" in str(det):
            det = str(det).split("T")[0]
        analyzer = r.get("analyzer_name", "—")
        fp       = short_path(file_path(r))
        ln       = r.get("line", "—")
        lines.append(
            f"| {status} | `{h}` | `{checker}` | {sev} | {det} | {analyzer} | {fp}:{ln} |"
        )
else:
    lines.append("_No new defects detected._")
lines.append("\n</details>\n")

# ── Fixed defects ──────────────────────────────────────────────────────────
lines.append("<details open><summary><b>Fixed defects:</b></summary>\n")
if resolved_reports:
    lines.append("| Status | Bug Hash | Type | Severity | Date | Analyzer | File |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in resolved_reports:
        h       = short_hash(r.get("report_hash", ""))
        checker = r.get("checker_name", "—")
        sev     = SEV_LABEL.get(r.get("severity", "").lower(), r.get("severity", "—"))
        analyzer= r.get("analyzer_name", "—")
        fp      = short_path(file_path(r))
        ln      = r.get("line", "—")
        lines.append(
            f"| 🟣 | `{h}` | `{checker}` | {sev} | {report_date} | {analyzer} | {fp}:{ln} |"
        )
else:
    lines.append("_No defects eliminated._")
lines.append("\n</details>\n")

# ── Legend ─────────────────────────────────────────────────────────────────
lines.append("### Status legend\n")
lines.append(
    "🔴 Fix pending &nbsp;·&nbsp; 🟡 Untriaged &nbsp;·&nbsp; "
    "🟢 Intentional &nbsp;·&nbsp; 🔵 Ignored &nbsp;·&nbsp; "
    "🟣 Fixed &nbsp;·&nbsp; ⚪ False positive\n"
)

# ── Conclusion ─────────────────────────────────────────────────────────────
lines.append("## Conclusion\n")
if new_reports:
    high_new = sum(
        1 for r in new_reports
        if r.get("severity", "").lower() in ("high", "critical")
    )
    msg_parts = [f"**{len(new_reports)} new finding(s)** introduced in `{target_ref}` vs `{scan_ref}`"]
    if high_new:
        msg_parts.append(f"including **{high_new} HIGH/CRITICAL**")
    if resolved_reports:
        msg_parts.append(f"and **{len(resolved_reports)} previously reported finding(s) resolved**")
    lines.append(", ".join(msg_parts) + ".")
elif resolved_reports:
    lines.append(
        f"No new findings introduced in `{target_ref}` vs `{scan_ref}`. "
        f"**{len(resolved_reports)} previously reported finding(s) resolved.**"
    )
else:
    lines.append(
        f"No new findings introduced and no previously reported findings resolved "
        f"in `{target_ref}` vs `{scan_ref}`."
    )
lines.append("")
lines.append(
    f"> _Generated by [CodeChecker](https://github.com/Ericsson/codechecker) "
    f"{cc_version} on {report_date}_"
)
lines.append("")

# ── Write output ──────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
with open(output_path, "w") as fh:
    fh.write("\n".join(lines))

print(f"report: {output_path}  ({len(new_reports)} new, {len(resolved_reports)} fixed, {total_count} total)")
PYEOF
