set -uo pipefail

OUT="reports/security-report.md"
SCA="reports/trivy-sca-results.json"
IMAGE="reports/trivy-image-results.json"
SBOM="reports/sbom.cyclonedx.json"
ZAP="reports/report_json.json"

: "${GITLEAKS_OUTCOME:=unknown}"
: "${SONAR_GATE_OUTCOME:=unknown}"
: "${PR_NUMBER:=n/a}"

vuln_total() { [ -s "$1" ] && jq '[.Results[]?.Vulnerabilities[]?] | length' "$1" 2>/dev/null || echo 0; }
sev_count()  { [ -s "$1" ] && jq --arg s "$2" '[.Results[]?.Vulnerabilities[]? | select(.Severity==$s)] | length' "$1" 2>/dev/null || echo 0; }

outcome_badge() {
  case "$1" in
    success) echo "✅ Passed" ;;
    failure) echo "❌ Failed" ;;
    *)       echo "➖ Not run" ;;
  esac
}

vuln_badge() {
  local file="$1"
  if [ ! -s "$file" ]; then echo "➖ No report"; return; fi
  local crit high total
  crit=$(sev_count "$file" CRITICAL); high=$(sev_count "$file" HIGH); total=$(vuln_total "$file")
  if [ "$total" -eq 0 ]; then echo "✅ Clean"
  elif [ "$crit" -gt 0 ]; then echo "🚨 ${crit} critical / ${total} total"
  elif [ "$high" -gt 0 ]; then echo "⚠️ ${high} high / ${total} total"
  else echo "⚠️ ${total} findings"; fi
}

gitleaks_badge=$(outcome_badge "$GITLEAKS_OUTCOME")
sonar_badge=$(outcome_badge "$SONAR_GATE_OUTCOME")
sca_badge=$(vuln_badge "$SCA")
image_badge=$(vuln_badge "$IMAGE")

sbom_badge="➖ No report"
[ -s "$SBOM" ] && sbom_badge="📦 $(jq '.components | length' "$SBOM") components"

zap_badge="➖ No report"
zap_total=0
if [ -s "$ZAP" ]; then
  zap_total=$(jq '[.site[]?.alerts[]?] | length' "$ZAP" 2>/dev/null || echo 0)
  zap_high=$(jq '[.site[]?.alerts[]? | select(.riskdesc | startswith("High"))] | length' "$ZAP" 2>/dev/null || echo 0)
  if [ "$zap_total" -eq 0 ]; then zap_badge="✅ No alerts"
  elif [ "$zap_high" -gt 0 ]; then zap_badge="🚨 ${zap_high} high / ${zap_total} alert types"
  else zap_badge="⚠️ ${zap_total} alert types"; fi
fi

{
  echo "# 🛡️ DevSecOps Security Report"
  echo ""
  echo "| | |"
  echo "|---|---|"
  echo "| **Repository** | ${GITHUB_REPOSITORY:-n/a} |"
  echo "| **Commit** | \`${GITHUB_SHA:-n/a}\` |"
  echo "| **Pull Request** | #${PR_NUMBER} |"
  echo "| **Generated** | $(date -u '+%Y-%m-%d %H:%M UTC') |"
  echo ""
  echo "## Overview"
  echo ""
  echo "| Stage | Tool | Result |"
  echo "|---|---|---|"
  echo "| 🔑 Secret Scan | Gitleaks | ${gitleaks_badge} |"
  echo "| 📦 Dependency Scan (SCA) | Trivy | ${sca_badge} |"
  echo "| 🐳 Container Image Scan | Trivy | ${image_badge} |"
  echo "| 📋 SBOM | Trivy | ${sbom_badge} |"
  echo "| 🕷️ DAST | OWASP ZAP | ${zap_badge} |"
  echo "| 🔍 SAST + Quality Gate | SonarQube | ${sonar_badge} |"
  echo ""

  for pair in "Dependency (SCA):$SCA" "Container Image:$IMAGE"; do
    label="${pair%%:*}"; file="${pair##*:}"
    echo "## 📦 Trivy — ${label}"
    echo ""
    if [ ! -s "$file" ]; then
      echo "_No report available._"; echo ""; continue
    fi
    total=$(vuln_total "$file")
    if [ "$total" -eq 0 ]; then echo "No vulnerabilities detected. ✅"; echo ""; continue; fi
    echo "| Severity | Count |"
    echo "|---|---|"
    for s in CRITICAL HIGH MEDIUM LOW; do
      c=$(sev_count "$file" "$s"); [ "$c" -gt 0 ] && echo "| ${s} | ${c} |"
    done
    echo ""
    echo "<details><summary>Critical & High findings</summary>"
    echo ""
    echo "| Severity | Package | Installed | Fixed | CVE |"
    echo "|---|---|---|---|---|"
    jq -r '
      [.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL" or .Severity=="HIGH")]
      | sort_by(.Severity)
      | .[0:60][]
      | "| \(.Severity) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion // "—") | \(.VulnerabilityID) |"
    ' "$file"
    echo ""
    echo "</details>"
    echo ""
  done

  echo "## 🕷️ DAST — OWASP ZAP"
  echo ""
  if [ ! -s "$ZAP" ]; then
    echo "_No report available._"; echo ""
  elif [ "$zap_total" -eq 0 ]; then
    echo "No alerts raised. ✅"; echo ""
  else
    echo "| Risk | Alert | Instances |"
    echo "|---|---|---|"
    jq -r '
      [.site[]?.alerts[]?]
      | sort_by(.riskcode | tonumber) | reverse
      | .[]
      | "| \(.riskdesc | split(" ")[0]) | \((.name // .alert) | gsub("\\|";"\\|")) | \(.count) |"
    ' "$ZAP"
    echo ""
  fi

  echo "## 📋 SBOM — Component Inventory"
  echo ""
  if [ ! -s "$SBOM" ]; then
    echo "_No report available._"; echo ""
  else
    echo "| Ecosystem | Count |"
    echo "|---|---|"
    jq -r '
      [.components[]? | (.purl // "pkg:unknown/") | capture("^pkg:(?<type>[a-zA-Z0-9.+-]+)/").type]
      | group_by(.) | map({type: .[0], count: length}) | sort_by(-.count)
      | .[] | "| \(.type) | \(.count) |"
    ' "$SBOM"
    echo ""
  fi

  echo "---"
  echo ""
  echo "_This report aggregates all pipeline scanners. Per-stage details are also"
  echo "available in the run's job summary and individual artifacts._"
} > "$OUT"

echo "Consolidated report written to ${OUT}"
