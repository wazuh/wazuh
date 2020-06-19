import os

output = os.system("grep -q 'wazuh-modulesd:ciscat: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")

if output == 0:
    exit(0)
else:
    exit(1)
