#!/usr/bin/env bash
set -euo pipefail

# --- Configurables ---
TEMPLATE="indexer-\$PLACEHOLDER.yml.template"  # Template file
BASE_DIR="/workspaces/wazuh-5.x/intelligence-data/ruleset/integrations"

# --- Placeholders to process ---
# Each placeholder corresponds to a subdirectory in $BASE_DIR containing a manifest.yml file.
# The script will generate an output file named indexer-<placeholder>.yml for each
PLACEHOLDERS=(
  cisco-umbrella
  squid
  azure-app-service
#  modsec
  modsecurity
#  spring-boot
  springboot
  microsoft-dhcp
# audit
  auditd
  zeek
  f5-bigip
  iis
  iptables
  microsoft-exchange-server
#  unifiedlogs
  macos-uls
  checkpoint
  gcp
  microsoft-dnsserver
  windows
  pfsense
  azure
  fortinet
  websphere
  cisco-asa
  azure-metrics
  amazon-security-lake
  oracle-weblogic
  suricata
  snort
  apache-tomcat
)

if [ ! -f "$TEMPLATE" ]; then
  echo "ERROR: the template file '$TEMPLATE' does not exist." >&2
  exit 1
fi

# --- Func: Build comma-separated decoder list ---
# Extracts decoder names from a manifest file and returns them as a comma-separated list.
#   - decoder/azure-activity/0
#   - decoders/azure-activity/0
build_integration_list() {
  manifest_file=$1

  if [ ! -f "$manifest_file" ]; then
    echo "ERROR: Manifest file not found: $manifest_file" >&2
    return 1
  fi

  # ^\s*-\s*decoder[s]*/\([^/][^/]*\)/0\s*$
  list=$(
    sed -n 's/^[[:space:]]*-[[:space:]]*decoder[s]*\/\([^\/][^\/]*\)\/0[[:space:]]*$/\1/p' \
      "$manifest_file" \
    | paste -sd ', ' -
  )

  if [ -z "$list" ]; then
    echo "ERROR: No decoders found in manifest: $manifest_file" >&2
    return 1
  fi

  printf '%s' "$list"
}

# --- Main ---
declare -A GENERATED_LISTS

for ph in "${PLACEHOLDERS[@]}"; do
  out_file="indexer-${ph}.yml"
  manifest="${BASE_DIR}/${ph}/manifest.yml"

  echo "Procesando: ${ph}"

  if ! list=$(build_integration_list "$manifest"); then
    echo "  -> Skipping '${ph}' due to errors." >&2
    continue
  fi

  # Replace placeholders in the template:
  #  - $PLACEHOLDER -> current placeholder
  #  - $INTEGRATIONLIST -> comma-separated list of decoders
  # Write to a temporary file first, then move to final destination if successful.
  tmp="${out_file}.tmp"
  if ! sed -e "s|\$PLACEHOLDER|${ph}|g" \
           -e "s|\$INTEGRATIONLIST|${list}|g" \
           "$TEMPLATE" > "$tmp"; then
    echo "  -> ERROR during generation of '${ph}'. Skipping." >&2
    rm -f "$tmp" || true
    continue
  fi

  mv -f "$tmp" "$out_file"
  GENERATED_LISTS["$ph"]="$list"
  echo "  -> generated: $out_file"
done

echo "Summary of generated decoder lists:"
echo -n "["
for ph in "${!GENERATED_LISTS[@]}"; do
  echo -n "${GENERATED_LISTS[$ph]}, "
done
# Delete trailing comma and space
echo -e "\b\b]"
echo -n "]"
