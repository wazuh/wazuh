# import os
#
# output_ciscat = os.system("grep -q 'wazuh-modulesd:ciscat: INFO: Scan finished successfully.' /var/ossec/logs/ossec.log")
# output_syscollector = os.system("grep -q 'wazuh-modulesd:syscollector: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")
# output_syscheck = os.system("grep -q 'ossec-syscheckd: INFO: (6009): File integrity monitoring scan ended.' /var/ossec/logs/ossec.log")
#
# if output_ciscat == 0 and output_syscollector == 0 and output_syscheck == 0:
#     exit(0)
# else:
#     exit(1)

# Provisionally
import os

def get_health():
    output = os.system("grep -q 'syscheckd: INFO: (6009): File integrity monitoring scan ended.' /var/ossec/logs/ossec.log")
    output_syscollector = os.system("grep -q 'wazuh-modulesd:syscollector: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")

    if output == 0 and output_syscollector == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(get_health())
