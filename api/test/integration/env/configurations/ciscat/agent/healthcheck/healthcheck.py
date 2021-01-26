import os

output = os.system("grep -q 'wazuh-modulesd:ciscat: INFO: Scan finished successfully.' /var/ossec/logs/ossec.log")

if output == 0:
    exit(0)
else:
    exit(1)
