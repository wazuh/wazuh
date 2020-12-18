import os


def get_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    check0 = os.popen("diff -q /tmp/output.txt /configuration_files/healthcheck/agent_control_check.txt").read()
    check1 = os.system("grep -q 'syscheckd: INFO: (6009): File integrity monitoring scan ended.' /var/ossec/logs/ossec.log")
    check2 = 0 if os.system("grep -qs 'Listening on ' /var/ossec/logs/api.log") == 0 else 1

    if "differ" not in check0 and check1 == 0 and check2 == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(get_health())
