import os

exit(os.system("grep -q 'wazuh-modulesd:ciscat: INFO: Evaluation finished.' /var/ossec/logs/ossec.log"))
