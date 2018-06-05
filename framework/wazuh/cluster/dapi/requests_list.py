#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import Wazuh
from wazuh import common
from wazuh.agent import Agent
from wazuh.rule import Rule
from wazuh.decoder import Decoder
import wazuh.cluster.cluster as cluster
import wazuh.cluster.control as cluster_control
import wazuh.configuration as configuration
import wazuh.manager as manager
import wazuh.stats as stats
import wazuh.rootcheck as rootcheck
import wazuh.syscheck as syscheck
import wazuh.syscollector as syscollector


functions = {
    # Agents
    '/agents/:agent_id': {
        'function': Agent.get_agent,
        'type': 'local_master'
    },
    '/agents/name/:agent_name': {
        'function': Agent.get_agent_by_name,
        'type': 'local_master'
    },
    '/agents/:agent_id/key': {
        'function': Agent.get_agent_key,
        'type': 'local_master'
    },
    '/agents': {
        'function': Agent.get_agents_overview,
        'type': 'local_master'
    },
    '/agents/summary': {
        'function': Agent.get_agents_summary,
        'type': 'local_master'
    },
    '/agents/summary/os': {
        'function': Agent.get_os_summary,
        'type': 'local_master'
    },
    '/agents/outdated': {
        'function': Agent.get_outdated_agents,
        'type': 'local_master'
    },
    '/agents/:agent_id/upgrade_result': {
        'function': Agent.get_upgrade_result,
        'type': 'local_master'
    },
    'PUT/agents/:agent_id/upgrade': {
        'function': Agent.upgrade_agent,
        'type': 'local_master'
    },
    'PUT/agents/:agent_id/upgrade_custom': {
        'function': Agent.upgrade_agent_custom,
        'type': 'local_master'
    },
    'PUT/agents/:agent_id/restart': {
        'function': Agent.restart_agents,
        'type': 'distributed_master'
    },
    'PUT/agents/restart': {
        'function': Agent.restart_agents,
        'type': 'distributed_master'
    },
    'PUT/agents/:agent_name': {
        'function': Agent.add_agent,
        'type': 'local_master'
    },
    'POST/agents/restart': {
        'function': Agent.restart_agents,
        'type': 'distributed_master'
    },
    'POST/agents': {
        'function': Agent.add_agent,
        'type': 'local_master'
    },
    'POST/agents/insert': {
        'function': Agent.insert_agent,
        'type': 'local_master'
    },
    'DELETE/agents/groups': {
        'function': Agent.remove_group,
        'type': 'local_master'
    },
    'DELETE/agents/:agent_id': {
        'function': Agent.remove_agent,
        'type': 'local_master'
    },
    'DELETE/agents/': {
        'function': Agent.remove_agent,
        'type': 'local_master'
    },

    # Groups
    '/agents/groups': {
        'function': Agent.get_all_groups,
        'type': 'local_master'
    },
    '/agents/no_group': {
        'function': Agent.get_agents_without_group,
        'type': 'local_master'
    },
    '/agents/groups/:group_id': {
        'function': Agent.get_agent_group,
        'type': 'local_master'
    },
    '/agents/groups/:group_id/configuration': {
        'function': configuration.get_agent_conf,
        'type': 'local_master'
    },
    '/agents/groups/:group_id/files': {
        'function': Agent.get_group_files,
        'type': 'local_master'
    },
    '/agents/groups/:group_id/files/:filename': {
        'function': configuration.get_file_conf,
        'type': 'local_master'
    },
    'PUT/agents/:agent_id/group/:group_id': {
        'function': Agent.set_group,
        'type': 'local_master'
    },
    'PUT/agents/groups/:group_id': {
        'function': Agent.create_group,
        'type': 'local_master'
    },
    'DELETE/agents/groups/:group_id': {
        'function': Agent.remove_group,
        'type': 'local_master'
    },
    'DELETE/agents/:agent_id/group': {
        'function': Agent.unset_group,
        'type': 'local_master'
    },

    # Decoders
    '/decoders': {
        'function': Decoder.get_decoders,
        'type': 'local_any'
    },
    '/decoders/files': {
        'function': Decoder.get_decoders_files,
        'type': 'local_master'
    },

    # Managers
    '/manager/info': {
        'function': Wazuh(common.ossec_path).get_ossec_init,
        'type': 'local_master'
    },
    '/manager/status': {
        'function': manager.status,
        'type': 'local_master'
    },
    '/manager/configuration': {
        'function': configuration.get_ossec_conf,
        'type': 'local_master'
    },
    '/manager/stats': {
        'function': stats.totals,
        'type': 'local_master'
    },
    '/manager/stats/hourly': {
        'function': stats.hourly,
        'type': 'local_master'
    },
    '/manager/stats/weekly': {
        'function': stats.weekly,
        'type': 'local_master'
    },
    '/manager/logs/summary': {
        'function': manager.ossec_log_summary,
        'type': 'local_master'
    },
    '/manager/logs': {
        'function': manager.ossec_log,
        'type': 'local_master'
    },

    # Cluster
    '/cluster/status': {
        'function': cluster.get_status_json,
        'type': 'local_master'
    },
    '/cluster/config': {
        'function': cluster.read_config,
        'type': 'local_master'
    },
    '/cluster/node': {
        'function': cluster.get_node,
        'type': 'local_master'
    },
    '/cluster/nodes': {
        'function': cluster_control.get_nodes_api,
        'type': 'local_master'
    },
    '/cluster/nodes/:node_name': {
        'function': cluster_control.get_nodes_api,
        'type': 'local_master'
    },
    '/cluster/healthcheck': {
        'function': cluster_control.get_healthcheck,
        'type': 'local_master'
    },

    # Rootcheck
    '/rootcheck/:agent_id': {
        'function': rootcheck.print_db,
        'type': 'local_master'
    },
    '/rootcheck/:agent_id/pci': {
        'function': rootcheck.get_pci,
        'type': 'local_master'
    },
    '/rootcheck/:agent_id/cis': {
        'function': rootcheck.get_cis,
        'type': 'local_master'
    },
    '/rootcheck/:agent_id/last_scan': {
        'function': rootcheck.last_scan,
        'type': 'local_master'
    },
    'PUT/rootcheck': {
        'function': rootcheck.run,
        'type': 'local_master'
    },
    'DELETE/rootcheck': {
        'function': rootcheck.clear,
        'type': 'local_master'
    },

    # Rules
    '/rules': {
        'function': Rule.get_rules,
        'type': 'local_master'
    },
    '/rules/groups': {
        'function': Rule.get_groups,
        'type': 'local_master'
    },
    '/rules/pci': {
        'function': Rule.get_pci,
        'type': 'local_master'
    },
    '/rules/gdpr': {
        'function': Rule.get_gdpr,
        'type': 'local_master'
    },
    '/rules/files': {
        'function': Rule.get_rules_files,
        'type': 'local_master'
    },

    # Syscheck
    '/syscheck/:agent_id': {
        'function': syscheck.files,
        'type': 'local_master'
    },
    '/syscheck/:agent_id/last_scan': {
        'function': syscheck.last_scan,
        'type': 'local_master'
    },
    'PUT/syscheck': {
        'function': syscheck.run,
        'type': 'local_master'
    },
    'DELETE/syscheck': {
        'function': syscheck.clear,
        'type': 'local_master'
    },

    # Syscollector
    '/syscollector/:agent_id/os': {
        'function': syscollector.get_os_agent,
        'type': 'local_master'
    },
    '/syscollector/:agent_id/hardware': {
        'function': syscollector.get_hardware_agent,
        'type': 'local_master'
    },
    '/syscollector/:agent_id/packages': {
        'function': syscollector.get_packages_agent,
        'type': 'local_master'
    },
    '/syscollector/os': {
        'function': syscollector.get_os,
        'type': 'local_master'
    },
    '/syscollector/hardware': {
        'function': syscollector.get_hardware,
        'type': 'local_master'
    },
    '/syscollector/packages': {
        'function': syscollector.get_packages,
        'type': 'local_master'
    },

}

