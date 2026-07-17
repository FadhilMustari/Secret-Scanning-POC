#!/usr/bin/env bash
set -uo pipefail

# Severity emoji mapping
severity_emoji() {
  case "$1" in
    CRITICAL) echo "🔴" ;;
    HIGH)     echo "🟠" ;;
    MEDIUM)   echo "🟡" ;;
    LOW)      echo "🔵" ;;
    *)        echo "⚪" ;;
  esac
}

# Count vulnerabilities by severity from a JSON file
count_by_severity() {
  local file="$1"
  local sev="$2"
  jq --arg sev "$sev" '[.Results[]?.Vulnerabilities[]? | select(.Severity==$sev)] | length' "$file"
}

# Count fixable vulnerabilities (have a FixedVersion)
count_fixable() {
  local file="$1"
  jq '[.Results[]?.Vulnerabilities[]? | select(.FixedVersion != null and .FixedVersion != "")] | length' "$file"
}

# Write detail table for a scan result file
write_detail_table() {
  local file="$1"
  local max_rows=50
  local total
  total=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$file")

  if [ "$total" -eq 0 ]; then
    echo "No vulnerabilities detected. ✅"
    echo ""
    return
  fi

  local fixable
  fixable=$(count_fixable "$file")

  echo "**$total vulnerabilities found** — $fixable fixable"
  echo ""
  echo "| Severity | Count | Fixable |"
  echo "|---|---|---|"
  for sev in CRITICAL HIGH MEDIUM LOW UNKNOWN; do
    count=$(count_by_severity "$file" "$sev")
    if [ "$count" -gt 0 ]; then
      fix_count=$(jq --arg sev "$sev" '[.Results[]?.Vulnerabilities[]? | select(.Severity==$sev and .FixedVersion != null and .FixedVersion != "")] | length' "$file")
      emoji=$(severity_emoji "$sev")
      echo "| ${emoji} ${sev} | ${count} | ${fix_count} of ${count} fixable |"
    fi
  done
  echo ""

  echo "<details><summary>View details (up to ${max_rows} entries)</summary>"
  echo ""
  echo "| | Package | Current Version | Fix Available | CVE |"
  echo "|---|---|---|---|---|"
  jq -r --argjson max "$max_rows" '
    [.Results[]?.Vulnerabilities[]?]
    | sort_by(.Severity as $s | ({"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"UNKNOWN":4}[$s] // 5))
    | .[0:$max][]
    | [
        (if .Severity == "CRITICAL" then "🔴"
         elif .Severity == "HIGH"     then "🟠"
         elif .Severity == "MEDIUM"   then "🟡"
         elif .Severity == "LOW"      then "🔵"
         else "⚪" end),
        .PkgName,
        .InstalledVersion,
        (if (.FixedVersion // "") == "" then "—" else "Upgrade to `" + .FixedVersion + "`" end),
        "[" + .VulnerabilityID + "](https://avd.aquasec.com/nvd/" + (.VulnerabilityID | ascii_downcase) + ")"
      ]
    | "| " + join(" | ") + " |"
  ' "$file"
  echo ""
  if [ "$total" -gt "$max_rows" ]; then
    echo "> Showing $max_rows of $total findings. See the **Security → Code scanning** tab for the full list."
    echo ""
  fi
  echo "</details>"
  echo ""
}

# ── Collect overall status ────────────────────────────────────────────────────
sca_file="reports/trivy-sca-results.json"
image_file="reports/trivy-image-results.json"

sca_total=0
image_total=0

[ -s "$sca_file" ]   && sca_total=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$sca_file")
[ -s "$image_file" ] && image_total=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$image_file")

sca_critical=0; sca_high=0
image_critical=0; image_high=0

if [ "$sca_total" -gt 0 ]; then
  sca_critical=$(count_by_severity "$sca_file" "CRITICAL")
  sca_high=$(count_by_severity "$sca_file" "HIGH")
fi
if [ "$image_total" -gt 0 ]; then
  image_critical=$(count_by_severity "$image_file" "CRITICAL")
  image_high=$(count_by_severity "$image_file" "HIGH")
fi

sca_status="✅ Clean"
[ "$sca_total" -gt 0 ] && sca_status="⚠️ ${sca_total} issues"
[ "$sca_critical" -gt 0 ] && sca_status="🚨 ${sca_critical} critical"

image_status="✅ Clean"
[ "$image_total" -gt 0 ] && image_status="⚠️ ${image_total} issues"
[ "$image_critical" -gt 0 ] && image_status="🚨 ${image_critical} critical"

# ── Write to summary ──────────────────────────────────────────────────────────
{
  echo "## 🛡️ Security Scan Results"
  echo ""
  echo "| Check | Status | Critical | High |"
  echo "|---|---|---|---|"
  echo "| 📦 Dependency Scan | ${sca_status} | ${sca_critical} | ${sca_high} |"
  echo "| 🐳 Container Scan | ${image_status} | ${image_critical} | ${image_high} |"
  echo ""

  echo "---"
  echo ""
  echo "### 📦 Dependency Vulnerabilities"
  echo ""
  if [ ! -s "$sca_file" ]; then
    echo "_Scan report not available._"
    echo ""
  else
    write_detail_table "$sca_file"
  fi

  echo "### 🐳 Container Vulnerabilities"
  echo ""
  if [ ! -s "$image_file" ]; then
    echo "_Scan report not available._"
    echo ""
  else
    write_detail_table "$image_file"
  fi

} >> "$GITHUB_STEP_SUMMARY"
