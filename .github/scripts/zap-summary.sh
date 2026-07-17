#!/usr/bin/env bash
set -uo pipefail

file="reports/report_json.json"

risk_emoji() {
  case "$1" in
    High)          echo "🔴" ;;
    Medium)        echo "🟠" ;;
    Low)           echo "🟡" ;;
    Informational) echo "🔵" ;;
    *)             echo "⚪" ;;
  esac
}

{
  echo "## 🕷️ DAST Results (OWASP ZAP)"
  echo ""

  if [ ! -s "$file" ]; then
    echo "_DAST report not available._"
    echo ""
  else
    total=$(jq '[.site[]?.alerts[]?] | length' "$file")

    if [ "$total" -eq 0 ]; then
      echo "No alerts raised. ✅"
      echo ""
    else
      echo "**${total} alert types found** across the scanned site."
      echo ""
      echo "| Risk | Count |"
      echo "|---|---|"
      for risk in High Medium Low Informational; do
        count=$(jq --arg r "$risk" '[.site[]?.alerts[]? | select(.riskdesc | startswith($r))] | length' "$file")
        if [ "$count" -gt 0 ]; then
          emoji=$(risk_emoji "$risk")
          echo "| ${emoji} ${risk} | ${count} |"
        fi
      done
      echo ""

      echo "<details><summary>View alert details</summary>"
      echo ""
      echo "| Risk | Alert | Instances |"
      echo "|---|---|---|"
      jq -r '
        [.site[]?.alerts[]?]
        | sort_by(.riskcode | tonumber) | reverse
        | .[]
        | [
            (.riskdesc | split(" ")[0]),
            ((.name // .alert) | gsub("\\|"; "\\|")),
            .count
          ]
        | "| " + join(" | ") + " |"
      ' "$file"
      echo ""
      echo "> Full report available in the **zap_scan** artifact (HTML)."
      echo ""
      echo "</details>"
      echo ""
    fi
  fi
} >> "$GITHUB_STEP_SUMMARY"
