import os
import re
import socket
import time


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
        output = os.popen(
            "grep 'agentd: INFO: Agent is restarting due to shared configuration changes."
            "\|agentd: INFO: (4102): Connected to the server' "
            "/var/ossec/logs/ossec.log").read().split("\n")[:-1]

        agent_restarted = False
        for log in output:
            if re.match(r'.*Agent is restarting due to shared configuration changes.*', log):
                agent_restarted = True
            if agent_restarted and re.match(r'.*Connected to the server.*', log):
                # Wait to avoid the worst case:
                # +10 seconds for the agent to report the worker
                # +10 seconds for the worker to report master
                # After this time, the agent appears as active in the master node
                time.sleep(20)
                return 0
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
