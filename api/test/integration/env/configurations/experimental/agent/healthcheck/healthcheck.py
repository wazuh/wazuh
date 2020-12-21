import os

output_ciscat_scan = os.system("grep -q 'wazuh-modulesd:ciscat: INFO: Scan finished successfully.' /var/ossec/logs/ossec.log")
output_ciscat_evaluation = os.system("grep -q 'wazuh-modulesd:ciscat: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")
output_sysc = os.system("grep -q 'wazuh-modulesd:syscollector: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")

if output_ciscat_scan == 0 and output_ciscat_evaluation == 0 and output_sysc == 0:
    exit(0)
else:
    exit(1)
