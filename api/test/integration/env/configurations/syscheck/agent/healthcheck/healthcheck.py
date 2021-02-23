import os

from base_healthcheck import get_agent_health_base


def get_health():
    output = os.system(
        "grep -q 'syscheckd: INFO: (6009): File integrity monitoring scan ended.' /var/ossec/logs/ossec.log")

    if output == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(get_health() or get_agent_health_base())
