import os
import socket
import time


def check(result):
    if "differ" in result:
        return 1
    else:
        return 0


def get_master_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    return check(os.popen("diff -q /tmp/output.txt /configuration_files/healthcheck/agent_control_check.txt").read())


def get_manager_health():
    os.system("/var/ossec/bin/ossec-control status > /tmp/daemons.txt")
    return check(os.popen("diff -q /tmp/daemons.txt /tmp/daemons.txt").read())


if __name__ == "__main__":
    exit(get_master_health()) if socket.gethostname() == 'wazuh-master' else exit(get_manager_health())
