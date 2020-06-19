import os

output = os.system("grep -q 'sca: INFO: Security Configuration Assessment scan finished.' /var/ossec/logs/ossec.log")

if output == 0:
    exit(0)
else:
    exit(1)
