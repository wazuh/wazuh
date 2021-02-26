import os

from base_healthcheck import get_agent_health_base

if __name__ == "__main__":
    exit(os.system(
        "grep -q 'sca: INFO: Security Configuration Assessment scan finished.' /var/ossec/logs/ossec.log")
         or get_agent_health_base())
