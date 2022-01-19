import os
import sys

sys.path.append('/tools')

from healthcheck_utils import get_agent_health_base, check

if __name__ == "__main__":
    # Check that the syscollector differences are sent. This is part of the DBs synchronization process, and it happens
    # after the scan (modules with debug = 2 is needed).

    # Uncomment this snippet when https://github.com/wazuh/wazuh/issues/11829 is solved
    # sync_sent_logs = ('DEBUG: Sync sent: {"component":'f'"{component}"' for component in
    #                   ('syscollector_processes', 'syscollector_osinfo', 'syscollector_ports', 'syscollector_hwinfo',
    #                    'syscollector_packages', 'syscollector_network_iface', 'syscollector_network_protocol',
    #                    'syscollector_network_address'))
    #
    # exit(any(check(os.system(f"grep -q '{log}' /var/ossec/logs/ossec.log")) for log in sync_sent_logs)
    #      or get_agent_health_base())

    # Remove this snippet when https://github.com/wazuh/wazuh/issues/11829 is solved
    exit(check(os.system("grep -q 'wazuh-modulesd:syscollector.*INFO: Evaluation finished.' /var/ossec/logs/ossec.log"))
         or get_agent_health_base())
