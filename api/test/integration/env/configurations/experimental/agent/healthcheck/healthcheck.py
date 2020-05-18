import os

output_ciscat = os.system("grep -q 'wazuh-modulesd:ciscat: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")
output_sysc = os.system("grep -q 'wazuh-modulesd:syscollector: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")

if output_ciscat == 0 and output_sysc == 0:
    exit(0)
else:
    exit(1)
