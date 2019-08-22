import os


def get_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    check = os.popen("diff -q /tmp/output.txt /tmp/agent_control_check.txt").read()

    if "differ" in check:
        return 1
    else:
        return 0


if __name__ == "__main__":
    exit(get_health())
