import os


def get_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    check = os.popen("diff -q /tmp/output.txt /configuration_files/healthcheck/agent_control_check.txt").read()
    output = os.system("grep -q 'ossec-syscheckd: INFO: (6009): File integrity monitoring scan ended.' /var/ossec/logs/ossec.log")

    if "differ" not in check and output == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(get_health())
