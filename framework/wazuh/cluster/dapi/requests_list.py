#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
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
import wazuh.ciscat as ciscat
import wazuh.active_response as active_response

# Requests types:
#   * local_master       -> requests that must be executed in the master node.
#   * distributed_master -> requests that the master node must forward to the worker nodes able to answer them.
#   * local_any          -> requests any node can answer to.
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
    '/agents/stats/distinct': {
        'function': Agent.get_distinct_agents,
        'type': 'local_master'
    },
    '/agents/:agent_id/upgrade_result': {
        'function': Agent.get_upgrade_result,
        'type': 'distributed_master'
    },
    '/agents/:agent_id/group/is_sync': {
        'function': Agent.get_sync_group,
        'type': 'local_master'
    },
    '/agents/:agent_id/config/:component/:configuration': {
        'function': Agent.get_config,
        'type': 'distributed_master'
    },
    'PUT/agents/:agent_id/upgrade': {
        'function': Agent.upgrade_agent,
        'type': 'distributed_master'
    },
    'PUT/agents/:agent_id/upgrade_custom': {
        'function': Agent.upgrade_agent_custom,
        'type': 'distributed_master'
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
    'DELETE/agents/:agent_id': {
        'function': Agent.remove_agent,
        'type': 'local_master'
    },
    'DELETE/agents/': {
        'function': Agent.remove_agents,
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
    'POST/agents/group/:group_id': {
        'function': Agent.set_group_list,
        'type': 'local_master'
    },
    'PUT/agents/groups/:group_id': {
        'function': Agent.create_group,
        'type': 'local_master'
    },
    'POST/agents/groups/:group_id/configuration': {
        'function': configuration.upload_group_file,
        'type': 'local_master'
    },
    'POST/agents/groups/:group_id/files/:file_name': {
        'function': configuration.upload_group_file,
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
    'DELETE/agents/group/:group_id': {
        'function': Agent.unset_group_list,
        'type': 'local_master'
    },
    'DELETE/agents/:agent_id/group/:group_id': {
        'function': Agent.unset_group,
        'type': 'local_master'
    },
    'DELETE/agents/groups': {
        'function': Agent.remove_group,
        'type': 'local_master'
    },

    # Decoders
    '/decoders': {
        'function': Decoder.get_decoders,
        'type': 'local_any'
    },
    '/decoders/files': {
        'function': Decoder.get_decoders_files,
        'type': 'local_any'
    },

    # Managers
    '/manager/info': {
        'function': Wazuh(common.ossec_path).get_ossec_init,
        'type': 'local_any'
    },
    '/manager/status': {
        'function': manager.status,
        'type': 'local_any'
    },
    '/manager/configuration': {
        'function': configuration.get_ossec_conf,
        'type': 'local_any'
    },
    '/manager/stats': {
        'function': stats.totals,
        'type': 'local_any'
    },
    '/manager/stats/hourly': {
        'function': stats.hourly,
        'type': 'local_any'
    },
    '/manager/stats/weekly': {
        'function': stats.weekly,
        'type': 'local_any'
    },
    '/manager/stats/analysisd': {
        'function': stats.analysisd,
        'type': 'local_any'
    },
    '/manager/stats/remoted': {
        'function': stats.remoted,
        'type': 'local_any'
    },
    '/manager/logs/summary': {
        'function': manager.ossec_log_summary,
        'type': 'local_any'
    },
    '/manager/logs': {
        'function': manager.ossec_log,
        'type': 'local_any'
    },

    # Cluster
    '/cluster/status': {
        'function': cluster.get_status_json,
        'type': 'local_master'
    },
    '/cluster/config': {
        'function': cluster.read_config,
        'type': 'local_any'
    },
    '/cluster/node': {
        'function': cluster.get_node,
        'type': 'local_any'
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
    '/cluster/:node_id/info': {
        'function': Wazuh(common.ossec_path).get_ossec_init,
        'type': 'distributed_master'
    },
    '/cluster/:node_id/status': {
        'function': manager.status,
        'type': 'distributed_master'
    },
    '/cluster/:node_id/configuration': {
        'function': configuration.get_ossec_conf,
        'type': 'distributed_master'
    },
    '/cluster/:node_id/stats': {
        'function': stats.totals,
        'type': 'distributed_master'
    },
    '/cluster/:node_id/stats/hourly': {
        'function': stats.hourly,
        'type': 'distributed_master'
    },
    '/cluster/:node_id/stats/weekly': {
        'function': stats.weekly,
        'type': 'distributed_master'
    },
    '/cluster/:node_id/stats/analysisd': {
        'function': stats.analysisd,
        'type': 'distributed_master'
    },
    '/cluster/:node_id/stats/remoted': {
        'function': stats.remoted,
        'type': 'distributed_master'
    },
    '/cluster/:node_id/logs/summary': {
        'function': manager.ossec_log_summary,
        'type': 'distributed_master'
    },
    '/cluster/:node_id/logs': {
        'function': manager.ossec_log,
        'type': 'distributed_master'
    },

    # Rootcheck
    '/rootcheck/:agent_id': {
        'function': rootcheck.print_db,
        'type': 'distributed_master'
    },
    '/rootcheck/:agent_id/pci': {
        'function': rootcheck.get_pci,
        'type': 'distributed_master'
    },
    '/rootcheck/:agent_id/cis': {
        'function': rootcheck.get_cis,
        'type': 'distributed_master'
    },
    '/rootcheck/:agent_id/last_scan': {
        'function': rootcheck.last_scan,
        'type': 'distributed_master'
    },
    'PUT/rootcheck': {
        'function': rootcheck.run,
        'type': 'distributed_master'
    },
    'DELETE/rootcheck': {
        'function': rootcheck.clear,
        'type': 'distributed_master'
    },

    # Rules
    '/rules': {
        'function': Rule.get_rules,
        'type': 'local_any'
    },
    '/rules/groups': {
        'function': Rule.get_groups,
        'type': 'local_any'
    },
    '/rules/pci': {
        'function': Rule.get_pci,
        'type': 'local_any'
    },
    '/rules/gdpr': {
        'function': Rule.get_gdpr,
        'type': 'local_any'
    },
    '/rules/files': {
        'function': Rule.get_rules_files,
        'type': 'local_any'
    },

    # Syscheck
    '/syscheck/:agent_id': {
        'function': syscheck.files,
        'type': 'distributed_master'
    },
    '/syscheck/:agent_id/last_scan': {
        'function': syscheck.last_scan,
        'type': 'distributed_master'
    },
    'PUT/syscheck': {
        'function': syscheck.run,
        'type': 'distributed_master'
    },
    'DELETE/syscheck/:agent_id': {
        'function': syscheck.clear,
        'type': 'distributed_master'
    },

    # Syscollector
    '/syscollector/:agent_id/os': {
        'function': syscollector.get_os_agent,
        'type': 'distributed_master'
    },
    '/syscollector/:agent_id/hardware': {
        'function': syscollector.get_hardware_agent,
        'type': 'distributed_master'
    },
    '/syscollector/:agent_id/packages': {
        'function': syscollector.get_packages_agent,
        'type': 'distributed_master'
    },
    '/syscollector/:agent_id/processes': {
        'function': syscollector.get_processes_agent,
        'type': 'distributed_master'
    },
    '/syscollector/:agent_id/ports': {
        'function': syscollector.get_ports_agent,
        'type': 'distributed_master'
    },
    '/syscollector/:agent_id/netaddr': {
        'function': syscollector.get_netaddr_agent,
        'type': 'distributed_master'
    },
    '/syscollector/:agent_id/netproto': {
        'function': syscollector.get_netproto_agent,
        'type': 'distributed_master'
    },
    '/syscollector/:agent_id/netiface': {
        'function': syscollector.get_netiface_agent,
        'type': 'distributed_master'
    },

    # CIS-CAT
    '/ciscat/:agent_id/results': {
        'function': ciscat.get_results_agent,
        'type': 'distributed_master'
    },

    # Active response
    '/PUT/active-response/:agent_id': {
        'function': active_response.run_command,
        'type': 'distributed_master'
    },

    # Experimental
    '/experimental/syscollector/os': {
        'function': syscollector.get_os,
        'type': 'distributed_master'
    },
    '/experimental/syscollector/hardware': {
        'function': syscollector.get_hardware,
        'type': 'distributed_master'
    },
    '/experimental/syscollector/packages': {
        'function': syscollector.get_packages,
        'type': 'distributed_master'
    },
    '/experimental/syscollector/processes': {
        'function': syscollector.get_processes,
        'type': 'distributed_master'
    },
    '/experimental/syscollector/ports': {
        'function': syscollector.get_ports,
        'type': 'distributed_master'
    },
    '/experimental/syscollector/netaddr': {
        'function': syscollector.get_netaddr,
        'type': 'distributed_master'
    },
    '/experimental/syscollector/netproto': {
        'function': syscollector.get_netproto,
        'type': 'distributed_master'
    },
    '/experimental/syscollector/netiface': {
        'function': syscollector.get_netiface,
        'type': 'distributed_master'
    },
    '/experimental/ciscat/results': {
        'function': ciscat.get_ciscat_results,
        'type': 'distributed_master'
    },
    'DELETE/experimental/syscheck': {
        'function': syscheck.clear,
        'type': 'distributed_master'
    },
}

