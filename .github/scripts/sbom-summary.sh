#!/usr/bin/env bash
set -uo pipefail

file="sbom.cyclonedx.json"

{
  echo "### 📋 Software Inventory"
  echo ""

  if [ ! -s "$file" ]; then
    echo "_Inventory report not available._"
    echo ""
  else
    total=$(jq '.components | length' "$file")
    echo "**$total components detected** across all ecosystems."
    echo ""
    echo "| Ecosystem | Count |"
    echo "|---|---|"
    jq -r '
      [.components[]? | (.purl // "pkg:unknown/") | capture("^pkg:(?<type>[a-zA-Z0-9.+-]+)/").type]
      | group_by(.)
      | map({type: .[0], count: length})
      | sort_by(-.count)
      | .[]
      | "| \(.type) | \(.count) |"
    ' "$file"
    echo ""
    echo "<details><summary>View full component list (up to 200 entries)</summary>"
    echo ""
    echo "| Name | Version | Type |"
    echo "|---|---|---|"
    jq -r '
      [.components[]?][0:200][]
      | "| \(.name) | \(.version // "—") | \(.type // "—") |"
    ' "$file"
    echo ""
    if [ "$total" -gt 200 ]; then
      echo "> Showing 200 of $total components. Download the **sbom-cyclonedx** artifact for the complete list."
      echo ""
    fi
    echo "</details>"
    echo ""
  fi
} >> "$GITHUB_STEP_SUMMARY"
