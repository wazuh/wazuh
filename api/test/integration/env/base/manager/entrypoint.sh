#!/usr/bin/env bash

# The manager configuration directory is fixed, outside the installation home.
CONF_DIR=/etc/wazuh-manager

# Copy a fixture tree laid out like the installed manager: its etc/ is the configuration directory, the
# rest goes under the installation home.
copy_manager_tree() {
  for entry in "$1"/*; do
    [ -e "$entry" ] || continue
    if [ "$(basename "$entry")" = "etc" ]; then
      cp -rf "$entry"/. "$CONF_DIR"/
    else
      cp -rf "$entry" /var/wazuh-manager/
    fi
  done
}

# Apply API configuration
copy_manager_tree /tmp_volume/config && chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/api

# Modify wazuh configuration file
for conf_file in /tmp_volume/configuration_files/*.conf; do
  python3 /tools/xml_parser.py $CONF_DIR/wazuh-manager.conf $conf_file
done

  sed -i "s:<node>127.0.0.1</node>:<node>$1</node>:g" $CONF_DIR/wazuh-manager.conf
  sed -i "s:<node_name>node01</node_name>:<node_name>$2</node_name>:g" $CONF_DIR/wazuh-manager.conf
  sed -i "s:validate_responses=False:validate_responses=True:g" /var/wazuh-manager/api/scripts/wazuh_manager_apid.py
  sed -i "s:<bind_addr>127.0.0.1</bind_addr>:<bind_addr>0.0.0.0</bind_addr>:g" $CONF_DIR/wazuh-manager.conf
  sed -i "s:<local_ip>127.0.0.1</local_ip>:<local_ip>0.0.0.0</local_ip>:g" $CONF_DIR/wazuh-manager.conf
  sed -i "/<cluster>/,/<\/cluster>/s:<key>.*</key>:<key>9d273b53510fef702b54a92e9cffc82e</key>:" $CONF_DIR/wazuh-manager.conf

if [ "$3" != "master" ]; then
    sed -i "s:<node_type>master</node_type>:<node_type>worker</node_type>:g" $CONF_DIR/wazuh-manager.conf
fi

copy_manager_tree /tmp_volume/configuration_files/config
chown root:wazuh-manager $CONF_DIR/client.keys
chown -R wazuh-manager:wazuh-manager /var/wazuh-manager/queue/db
chown -R wazuh-manager:wazuh-manager $CONF_DIR/shared
chmod --reference=$CONF_DIR/shared/default $CONF_DIR/shared/group*
cd $CONF_DIR/shared && find -name merged.mg -exec chown wazuh-manager:wazuh-manager {} \; && cd /

sleep 1

# Manager configuration
for py_file in /tmp_volume/configuration_files/*.py; do
  /var/wazuh-manager/framework/python/bin/python3 $py_file
done

for sh_file in /tmp_volume/configuration_files/*.sh; do
  . $sh_file
done

# The start resolves credentials first and refuses to run without them. The tavern suites log in as
# wazuh-internal-client with a known password, and this environment has no indexer, so its value only has to be
# present. Same values on every node: they share the api_security volume, which the master seeds and the workers
# never do.
export WAZUH_MANAGER_API_PASSWORD='Wazuh-Integration1'
export WAZUH_MANAGER_WUI_PASSWORD='WazuhWui-Integration1'
export WAZUH_INDEXER_MANAGER_PASSWORD='Indexer-Integration1'

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
