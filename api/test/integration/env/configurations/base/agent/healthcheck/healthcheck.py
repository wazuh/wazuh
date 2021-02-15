import os
import re
from datetime import datetime


def get_timestamp(log):
    # Get timestamp from log
    # Log example:
    # 2021/02/15 12:37:04 wazuh-agentd: INFO: Agent is restarting due to shared configuration changes.
    timestamp = re.search(r'^[0-9]{4}-1[0-2]|0[1-9]-3[01]|0[1-9]|[12][0-9][tT]2[0-3]|[01][0-9]:[0-5][0-9]:[0-5][0-9]\.['
                          r'0-9]+?[zZ]|[+-]?:2[0-3]|[01][0-9]:[0-5][0-9]', log).group(0)

    t = datetime.strptime(timestamp, "%Y/%m/%d %H:%M:%S")

    return t


def get_health():
    # Get agent health. The agent will be healthy if it has been connected to the manager after been
    # restarted due to a shared configuration changes

    shared_conf_restart = os.system(
        "grep -q 'wazuh-agentd: INFO: Agent is restarting due to shared configuration changes.' "
        "/var/ossec/logs/ossec.log")
    agent_connection = os.system(
        "grep -q 'wazuh-agentd: INFO: (4102): Connected to the server' /var/ossec/logs/ossec.log")

    if shared_conf_restart == 0 and agent_connection == 0:
        output_agent_restart = os.popen(
            "grep -q 'wazuh-agentd: INFO: Agent is restarting due to shared configuration changes.' "
            "/var/ossec/logs/ossec.log").read().split()
        output_agent_connection = os.popen(
            "grep -q 'wazuh-agentd: INFO: (4102): Connected to the server' /var/ossec/logs/ossec.log").read().split()

        t1 = get_timestamp(output_agent_restart[len(output_agent_restart) - 1])
        t2 = get_timestamp(output_agent_connection[len(output_agent_connection) - 1])

        return 0 if t2 > t1 else 1
    return 1


if __name__ == "__main__":
    exit(get_health())
