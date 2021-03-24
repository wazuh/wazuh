import os
import re
import socket
from datetime import datetime


def get_timestamp(log):
    # Get timestamp from log.
    # Log example:
    # 2021/02/15 12:37:04 wazuh-agentd: INFO: Agent is restarting due to shared configuration changes.
    timestamp = re.search(r'^\d\d\d\d/\d\d/\d\d\s\d\d:\d\d:\d\d', log).group(0)

    t = datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S")

    return t


def get_agent_health_base():
    # Get agent health. The agent will be healthy if it has been connected to the manager after been
    # restarted due to shared configuration changes.
    # Using agentd when using grep as the module name can vary between ossec-agentd and wazuh-agentd,
    # depending on the agent version.

    shared_conf_restart = os.system(
        "grep -q 'agentd: INFO: Agent is restarting due to shared configuration changes.' "
        "/var/ossec/logs/ossec.log")
    agent_connection = os.system(
        "grep -q 'agentd: INFO: (4102): Connected to the server' /var/ossec/logs/ossec.log")

    if shared_conf_restart == 0 and agent_connection == 0:
        # No -q option as we need the output
        output_agent_restart = os.popen(
            "grep 'agentd: INFO: Agent is restarting due to shared configuration changes.' "
            "/var/ossec/logs/ossec.log").read().split("\n")
        output_agent_connection = os.popen(
            "grep 'agentd: INFO: (4102): Connected to the server' /var/ossec/logs/ossec.log").read().split("\n")

        t1 = get_timestamp(output_agent_restart[-2])
        t2 = get_timestamp(output_agent_connection[-2])

        return 0 if t2 > t1 else 1
    return 1


def check(result):
    if result == 0:
        return 0
    else:
        return 1


def get_master_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    os.system("/var/ossec/bin/wazuh-control status > /tmp/daemons.txt")
    check0 = check(os.system("diff -q /tmp/output.txt /tmp/healthcheck/agent_control_check.txt"))
    check1 = check(os.system("diff -q /tmp/daemons.txt /tmp/healthcheck/daemons_check.txt"))
    check2 = check(os.system("grep -qs 'Listening on ' /var/ossec/logs/api.log"))
    return check0 or check1 or check2


def get_worker_health():
    os.system("/var/ossec/bin/wazuh-control status > /tmp/daemons.txt")
    check0 = check(os.system("diff -q /tmp/daemons.txt /tmp/healthcheck/daemons_check.txt"))
    check1 = check(os.system("grep -qs 'Listening on ' /var/ossec/logs/api.log"))
    return check0 or check1


def get_manager_health_base():
    return get_master_health() if socket.gethostname() == 'wazuh-master' else get_worker_health()
