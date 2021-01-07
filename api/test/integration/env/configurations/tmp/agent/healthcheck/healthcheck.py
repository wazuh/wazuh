import os

def get_health():
    output = os.system("grep -q 'wazuh-modulesd:syscollector: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")

    if output == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(get_health())
