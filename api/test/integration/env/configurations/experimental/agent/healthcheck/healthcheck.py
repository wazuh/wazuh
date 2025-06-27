import os
import sys

sys.path.append('/tools')

from healthcheck_utils import get_agent_health_base, check

if __name__ == "__main__":
    if code := get_agent_health_base():
        exit(code)

    # Check that the syscollector differences are sent. This is part of the DBs synchronization process, and it happens
    # after the scan (modules with debug = 2 is needed).
    sync_sent_logs = ('DEBUG: Sync sent: {"component":'f'"{component}"' for component in
                      ('syscollector_processes', 'syscollector_osinfo', 'syscollector_ports', 'syscollector_hwinfo',
                       'syscollector_packages', 'syscollector_network_iface', 'syscollector_network_protocol',
                       'syscollector_network_address'))

    exit(any(check(os.system(f"grep -q '{log}' /var/ossec/logs/ossec.log")) for log in sync_sent_logs))
