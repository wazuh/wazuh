#!/bin/bash

echo "------------------------------------------------------------------" > initial_state.txt
echo "" >> initial_state.txt
echo "ls -lah --time-style=+"" / /var/ /usr/lib/ /usr/lib/systemd/ /usr/lib/systemd/system/ /etc/ /etc/systemd/ /etc/systemd/system/ /etc/rc.d/init.d/ /etc/rc.d " >> initial_state.txt
echo "" >> initial_state.txt
echo "$(ls -lah --time-style=+"" / /var/ /usr/lib/ /usr/lib/systemd/ /usr/lib/systemd/system/ /etc/ /etc/systemd/ /etc/systemd/system/ /etc/init.d/ /etc/rc.d/init.d/ /etc/rc.d )" >> initial_state.txt
echo "" >> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "" >> initial_state.txt
echo "tree -pugh /var/ossec" >> initial_state.txt
echo "" >> initial_state.txt
echo "$(tree -pugh /var/ossec)"	>> initial_state.txt
echo "" >> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "" >> initial_state.txt
echo "cat /etc/rc.d/init.d/wazuh-agent" >> initial_state.txt
echo "" >> initial_state.txt
echo "$(cat /etc/rc.d/init.d/wazuh-agent)" >> initial_state.txt
echo "" >> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "" >> initial_state.txt
echo "cat /etc/init.d/wazuh-agent" >> initial_state.txt
echo "" >> initial_state.txt
echo "$(cat /etc/init.d/wazuh-agent)" >> initial_state.txt
echo "" >> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "" >> initial_state.txt
echo "chkconfig --list | grep 'wazuh\|ossec'" >> initial_state.txt
echo "" >> initial_state.txt
echo "$(chkconfig --list | grep 'wazuh\|ossec')" >> initial_state.txt
echo ""	>> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "" >> initial_state.txt
echo "cat /var/ossec/var/run/ossec-agentd.state" >> initial_state.txt
echo "" >> initial_state.txt
echo "$(cat /var/ossec/var/run/ossec-agentd.state)" >> initial_state.txt
echo "" >> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "" >> initial_state.txt
echo "cat /var/ossec/var/run/wazuh-agentd.state" >> initial_state.txt
echo "" >> initial_state.txt
echo "$(cat /var/ossec/var/run/wazuh-agentd.state)" >> initial_state.txt
echo "" >> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "" >> initial_state.txt
echo "semodule -l | grep -i 'wazuh\|ossec'" >> initial_state.txt
echo "" >> initial_state.txt
echo "$(semodule -l | grep -i 'wazuh\|ossec')" >> initial_state.txt
echo "" >> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "" >> initial_state.txt
echo "systemctl is-enabled wazuh-agent.service" >> initial_state.txt
echo "" >> initial_state.txt
echo "$(systemctl is-enabled wazuh-agent.service)" >> initial_state.txt
echo "" >> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "" >> initial_state.txt
echo "systemctl cat wazuh-agent.service" >> initial_state.txt
echo "" >> initial_state.txt
echo "$(systemctl cat wazuh-agent.service)" >> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "cat /etc/passwd" >> initial_state.txt
cat /etc/passwd >> initial_state.txt

echo "------------------------------------------------------------------" >> initial_state.txt
echo "cat /etc/group"  >> initial_state.txt
cat /etc/group >> initial_state.txt




