#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import Wazuh
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
    '/agents/:agent_id': Agent.get_agent,
    '/agents/name/:agent_name': Agent.get_agent_by_name,
    '/agents/:agent_id/key': Agent.get_agent_key,
    '/agents': Agent.get_agents_overview,
    '/agents/summary': Agent.get_agents_summary,
    '/agents/summary/os': Agent.get_os_summary,
    '/agents/outdated': Agent.get_outdated_agents,
    '/agents/:agent_id/upgrade_result': Agent.get_upgrade_result,
    'PUT/agents/:agent_id/upgrade': Agent.upgrade_agent,
    'PUT/agents/:agent_id/upgrade_custom': Agent.upgrade_agent_custom,
    'PUT/agents/:agent_id/restart': Agent.restart_agents,
    'PUT/agents/restart': Agent.restart_agents,
    'PUT/agents/:agent_name': Agent.add_agent,
    'POST/agents/restart': Agent.restart_agents,
    'POST/agents': Agent.add_agent,
    'POST/agents/insert': Agent.insert_agent,
    'DELETE/agents/groups': Agent.remove_group,
    'DELETE/agents/:agent_id': Agent.remove_agent,
    'DELETE/agents/': Agent.remove_agent,

    # Groups
    '/agents/groups': Agent.get_all_groups,
    '/agents/no_group': Agent.get_agents_without_group,
    '/agents/groups/:group_id': Agent.get_agent_group,
    '/agents/groups/:group_id/configuration':configuration.get_agent_conf,
    '/agents/groups/:group_id/files':Agent.get_group_files,
    '/agents/groups/:group_id/files/:filename':configuration.get_file_conf,
    'PUT/agents/:agent_id/group/:group_id': Agent.set_group,
    'PUT/agents/groups/:group_id': Agent.create_group,
    'DELETE/agents/groups/:group_id':Agent.remove_group,
    'DELETE/agents/:agent_id/group':Agent.unset_group,

    # Decoders
    '/decoders': Decoder.get_decoders,
    '/decoders/files': Decoder.get_decoders_files,

    # Managers
    '/manager/info': Wazuh.get_ossec_init,
    '/manager/status': manager.status,
    '/manager/configuration': configuration.get_ossec_conf,
    '/manager/stats': stats.totals,
    '/manager/stats/hourly': stats.hourly,
    '/manager/stats/weekly': stats.weekly,
    '/manager/logs/summary': manager.ossec_log_summary,
    '/manager/logs': manager.ossec_log,

    # Cluster
    '/cluster/status': cluster.get_status_json,
    '/cluster/config': cluster.read_config,
    '/cluster/node': cluster.get_node,
    '/cluster/nodes': cluster_control.get_nodes_api,
    '/cluster/nodes/:node_name': cluster_control.get_nodes_api,
    '/cluster/healthcheck': cluster_control.get_healthcheck,

    # Rootcheck
    '/rootcheck/:agent_id': rootcheck.print_db,
    '/rootcheck/:agent_id/pci': rootcheck.get_pci,
    '/rootcheck/:agent_id/cis': rootcheck.get_cis,
    '/rootcheck/:agent_id/last_scan': rootcheck.last_scan,
    'PUT/rootcheck': rootcheck.run,
    'DELETE/rootcheck': rootcheck.clear,

    # Rules
    '/rules': Rule.get_rules,
    '/rules/groups': Rule.get_groups,
    '/rules/pci': Rule.get_pci,
    '/rules/gdpr': Rule.get_gdpr,
    '/rules/files': Rule.get_rules_files,

    # Syscheck
    '/syscheck/:agent_id': syscheck.files,
    '/syscheck/:agent_id/last_scan': syscheck.last_scan,
    'PUT/syscheck': syscheck.run,
    'DELETE/syscheck': syscheck.clear,

    # Syscollector
    '/syscollector/:agent_id/os': syscollector.get_os_agent,
    '/syscollector/:agent_id/hardware': syscollector.get_hardware_agent,
    '/syscollector/:agent_id/packages': syscollector.get_packages_agent,
    '/syscollector/os': syscollector.get_os,
    '/syscollector/hardware': syscollector.get_hardware,
    '/syscollector/packages': syscollector.get_packages

}

