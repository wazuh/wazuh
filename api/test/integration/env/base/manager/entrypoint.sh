#!/usr/bin/env bash

# Apply API configuration
cp -rf /tmp_volume/config/* /var/ossec/ && chown -R wazuh:wazuh /var/ossec/api

# Modify ossec.conf
for conf_file in /tmp_volume/configuration_files/*.conf; do
  python3 /tools/xml_parser.py /var/ossec/etc/ossec.conf $conf_file
done

if [ $4 == "standalone" ]; then
  sed -i -e "/<cluster>/,/<\/cluster>/ s|<disabled>[a-z]\+</disabled>|<disabled>yes</disabled>|g" /var/ossec/etc/ossec.conf
else
  sed -i "s:<key>key</key>:<key>9d273b53510fef702b54a92e9cffc82e</key>:g" /var/ossec/etc/ossec.conf
  sed -i "s:<node>NODE_IP</node>:<node>$1</node>:g" /var/ossec/etc/ossec.conf
  sed -i "s:<node_name>node01</node_name>:<node_name>$2</node_name>:g" /var/ossec/etc/ossec.conf
  sed -i "s:validate_responses=False:validate_responses=True:g" /var/ossec/api/scripts/wazuh_apid.py
fi

if [ "$3" != "master" ]; then
    sed -i "s:<node_type>master</node_type>:<node_type>worker</node_type>:g" /var/ossec/etc/ossec.conf
fi

cp -rf /tmp_volume/configuration_files/config/* /var/ossec/
chown root:wazuh /var/ossec/etc/client.keys
chown -R wazuh:wazuh /var/ossec/queue/db
chown -R wazuh:wazuh /var/ossec/etc/shared
chmod --reference=/var/ossec/etc/shared/default /var/ossec/etc/shared/group*
cd /var/ossec/etc/shared && find -name merged.mg -exec chown wazuh:wazuh {} \; && cd /
chown root:wazuh /var/ossec/etc/shared/ar.conf

sleep 1

# Manager configuration
for py_file in /tmp_volume/configuration_files/*.py; do
  /var/ossec/framework/python/bin/python3 $py_file
done

for sh_file in /tmp_volume/configuration_files/*.sh; do
  . $sh_file
done

echo "" > /var/ossec/logs/api.log
/var/ossec/bin/wazuh-control start

# Master-only configuration
if [ "$3" == "master" ]; then
  for py_file in /tmp_volume/configuration_files/master_only/*.py; do
    /var/ossec/framework/python/bin/python3 $py_file
  done

  for sh_file in /tmp_volume/configuration_files/master_only/*.sh; do
    . $sh_file
  done

  exit_flag=0
  [ -e /entrypoint_error ] && rm -f /entrypoint_error
  # Wait until Wazuh API is ready
  elapsed_time=0
  while [[ $(grep -c 'Listening on' /var/ossec/logs/api.log)  -eq 0 ]] && [[ $exit_flag -eq 0 ]]
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
    sqlite3 /var/ossec/api/configuration/security/rbac.db < $sql_file > /tmp_volume/sql_lock_check 2>&1

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
      sqlite3 /var/ossec/api/configuration/security/rbac.db < $sql_file > /tmp_volume/sql_lock_check 2>&1
    done

    # Remove the temporal file used to check the possible locked database error
    rm -rf /tmp_volume/sql_lock_check
  done
fi

/usr/bin/supervisord
