#!/bin/bash

echo "------------------------------------------------------------------" > final_state.txt
echo "" >> final_state.txt
echo "ls -lah --time-style=+"" / /var/ /usr/lib/ /usr/lib/systemd/ /usr/lib/systemd/system/ /etc/ /etc/systemd/ /etc/systemd/system/ /etc/rc.d/init.d/ /etc/rc.d " >> final_state.txt
echo "" >> final_state.txt
echo "$(ls -lah --time-style=+"" / /var/ /usr/lib/ /usr/lib/systemd/ /usr/lib/systemd/system/ /etc/ /etc/systemd/ /etc/systemd/system/ /etc/init.d/ /etc/rc.d/init.d/ /etc/rc.d )" >> final_state.txt
echo "" >> final_state.txt

echo "------------------------------------------------------------------" >> final_state.txt
echo "" >> final_state.txt
echo "tree -pugh /var/ossec" >> final_state.txt
echo "" >> final_state.txt
echo "$(tree -pugh /var/ossec)"	>> final_state.txt
echo "" >> final_state.txt

echo "------------------------------------------------------------------" >> final_state.txt
echo "" >> final_state.txt
echo "cat /etc/rc.d/init.d/wazuh-agent" >> final_state.txt
echo "" >> final_state.txt
echo "$(cat /etc/rc.d/init.d/wazuh-agent)" >> final_state.txt
echo "" >> final_state.txt

echo "------------------------------------------------------------------" >> final_state.txt
echo "" >> final_state.txt
echo "cat /etc/init.d/wazuh-agent" >> final_state.txt
echo "" >> final_state.txt
echo "$(cat /etc/init.d/wazuh-agent)" >> final_state.txt
echo "" >> final_state.txt

echo "------------------------------------------------------------------" >> final_state.txt
echo "" >> final_state.txt
echo "chkconfig --list | grep 'wazuh\|ossec'" >> final_state.txt
echo "" >> final_state.txt
echo "$(chkconfig --list | grep 'wazuh\|ossec')" >> final_state.txt
echo ""	>> final_state.txt

echo "------------------------------------------------------------------" >> final_state.txt
echo "" >> final_state.txt
echo "cat /var/ossec/var/run/ossec-agentd.state" >> final_state.txt
echo "" >> final_state.txt
echo "$(cat /var/ossec/var/run/ossec-agentd.state)" >> final_state.txt
echo "" >> final_state.txt

echo "------------------------------------------------------------------" >> final_state.txt
echo "" >> final_state.txt
echo "cat /var/ossec/var/run/wazuh-agentd.state" >> final_state.txt
echo "" >> final_state.txt
echo "$(cat /var/ossec/var/run/wazuh-agentd.state)" >> final_state.txt
echo "" >> final_state.txt

echo "------------------------------------------------------------------" >> final_state.txt
echo "" >> final_state.txt
echo "semodule -l | grep -i 'wazuh\|ossec'" >> final_state.txt
echo "" >> final_state.txt
echo "$(semodule -l | grep -i 'wazuh\|ossec')" >> final_state.txt
echo "" >> final_state.txt

echo "------------------------------------------------------------------" >> final_state.txt
echo "" >> final_state.txt
echo "systemctl is-enabled wazuh-agent.service" >> final_state.txt
echo "" >> final_state.txt
echo "$(systemctl is-enabled wazuh-agent.service)" >> final_state.txt
echo "" >> final_state.txt

echo "------------------------------------------------------------------" >> final_state.txt
echo "" >> final_state.txt
echo "systemctl cat wazuh-agent.service" >> final_state.txt
echo "" >> final_state.txt
echo "$(systemctl cat wazuh-agent.service)" >> final_state.txt

echo "------------------------------------------------------------------" >> final_state.txt
echo "cat /etc/passwd" >> final_state.txt
cat /etc/passwd >> final_state.txt

echo "------------------------------------------------------------------" >>  final_state.txt
echo "cat /etc/group"  >> final_state.txt
cat /etc/group >> final_state.txt


echo ""
echo "------------------------------------------------------------------"
echo ""
echo "Differences: "
diff initial_state.txt final_state.txt
