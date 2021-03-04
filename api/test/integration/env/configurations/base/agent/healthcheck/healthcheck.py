import os
import re
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


if __name__ == "__main__":
    exit(get_agent_health_base())
