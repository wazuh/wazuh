import os
import sys

sys.path.append('/tools')

from healthcheck_utils import get_agent_health_base, check

if __name__ == "__main__":
    # Check that the syscollector differences are sent. This is part of the DBs synchronization process, and it happens
    # after the scan (modules with debug = 2 is needed).
    components = ('syscollector_processes', 'syscollector_osinfo', 'syscollector_ports', 'syscollector_hwinfo',
                  'syscollector_packages', 'syscollector_network_iface', 'syscollector_network_protocol',
                  'syscollector_network_address')
    strings_to_grep = ('DEBUG: Sync sent: {"component":' + f'"{component}"' for component in components)

    checks = (check(os.system(f"grep -q '{s}' /var/ossec/logs/ossec.log")) for s in strings_to_grep)
    exit(any(checks) or get_agent_health_base())
