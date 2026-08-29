#!/usr/bin/env bash

# Apply API configuration
cp -rf /tmp_volume/config/* /var/wazuh-manager/ && chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/api

# Modify the manager configuration file (etc/wazuh-manager.yml): merge the YAML fragments of the environment, then
# set the node-specific options. PyYAML comes with the manager's Python.
MANAGER_CONF=/var/wazuh-manager/etc/wazuh-manager.yml
YAML_MERGE="/var/wazuh-manager/framework/python/bin/python3 /tools/yaml_merge.py"
for conf_file in /tmp_volume/configuration_files/*.yml; do
  [ -e "$conf_file" ] && $YAML_MERGE merge $MANAGER_CONF $conf_file
done

  $YAML_MERGE set $MANAGER_CONF cluster.nodes "[$1]"
  $YAML_MERGE set $MANAGER_CONF cluster.node_name "$2"
  sed -i "s:validate_responses=False:validate_responses=True:g" /var/wazuh-manager/api/scripts/wazuh_manager_apid.py
  $YAML_MERGE set $MANAGER_CONF cluster.bind_addr 0.0.0.0
  $YAML_MERGE set $MANAGER_CONF remote.legacy.local_ip 0.0.0.0
  $YAML_MERGE set $MANAGER_CONF cluster.key 9d273b53510fef702b54a92e9cffc82e

if [ "$3" != "master" ]; then
    $YAML_MERGE set $MANAGER_CONF cluster.node_type worker
fi

cp -rf /tmp_volume/configuration_files/config/* /var/wazuh-manager/
chown root:wazuh-manager /var/wazuh-manager/etc/client.keys
chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/queue/db
chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/etc/shared
chmod --reference=/var/wazuh-manager/etc/shared/default /var/wazuh-manager/etc/shared/group*
cd /var/wazuh-manager/etc/shared && find -name merged.mg -exec chown wazuh-manager:wazuh-manager {} \; && cd /

sleep 1

# Manager configuration
for py_file in /tmp_volume/configuration_files/*.py; do
  /var/wazuh-manager/framework/python/bin/python3 $py_file
done

for sh_file in /tmp_volume/configuration_files/*.sh; do
  . $sh_file
done

# API SSL sync (only when cluster + shared ssl volume)
SSL_DIR="/var/wazuh-manager/etc/certs"
SSL_KEY="${SSL_DIR}/apid-key.pem"
SSL_CRT="${SSL_DIR}/apid.pem"

if [ "$4" != "standalone" ] && [ "$3" != "master" ]; then
  echo "[entrypoint] Worker waiting for shared API SSL files..."
  elapsed_time=0
  while [ ! -s "$SSL_KEY" ] || [ ! -s "$SSL_CRT" ]; do
    if [ $elapsed_time -gt 120 ]; then
      echo "Timeout waiting for API SSL files ($SSL_KEY, $SSL_CRT)" >&2
      exit 1
    fi
    sleep 1
    elapsed_time=$((elapsed_time+1))
  done
fi

echo "" > /var/wazuh-manager/logs/api.log
/var/wazuh-manager/bin/wazuh-manager-control start

# Master-only configuration
if [ "$3" == "master" ]; then
  for py_file in /tmp_volume/configuration_files/master_only/*.py; do
    /var/wazuh-manager/framework/python/bin/python3 $py_file
  done

  for sh_file in /tmp_volume/configuration_files/master_only/*.sh; do
    . $sh_file
  done

  exit_flag=0
  [ -e /entrypoint_error ] && rm -f /entrypoint_error
  # Wait until Wazuh API is ready
  elapsed_time=0
  while [[ $(grep -c 'Listening on' /var/wazuh-manager/logs/api.log)  -eq 0 ]] && [[ $exit_flag -eq 0 ]]
  do
    if [ $elapsed_time -gt 300 ]; then
      echo "Timeout on API callback. Could not find 'Listening on'" > /entrypoint_error
      exit_flag=1
    fi
    sleep 1
    elapsed_time=$((elapsed_time+1))
  done

  # RBAC configuration
  for sql_file in /tmp_volume/configuration_files/*.sql; do
    # Redirect standard error to /tmp_volume/sql_lock_check to check a possible locked database error
    # 2>&1 redirects "standard error" to "standard output"
    sqlite3 /var/wazuh-manager/api/configuration/security/rbac.db < $sql_file > /tmp_volume/sql_lock_check 2>&1

    # Insert the RBAC configuration again if database was locked
    elapsed_time=0
    while [[ $(grep -c 'database is locked' /tmp_volume/sql_lock_check)  -eq 1 ]] && [[ $exit_flag -eq 0 ]]
    do
      if [ $elapsed_time -gt 120 ]; then
        echo "Timeout on RBAC DB callback. Could not apply SQL file to RBAC DB" > /entrypoint_error
        exit_flag=1
      fi
      sleep 1
      elapsed_time=$((elapsed_time+1))
      sqlite3 /var/wazuh-manager/api/configuration/security/rbac.db < $sql_file > /tmp_volume/sql_lock_check 2>&1
    done

    # Remove the temporal file used to check the possible locked database error
    rm -rf /tmp_volume/sql_lock_check
  done
fi

/usr/bin/supervisord
