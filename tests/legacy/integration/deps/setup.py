# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from setuptools import setup, find_packages
import os

package_data_list = [
    'data/agent.conf',
    'data/syscheck_event.json',
    'data/syscheck_event_windows.json',
    'data/mitre_event.json',
    'data/analysis_alert.json',
    'data/analysis_alert_windows.json',
    'data/state_integrity_analysis_schema.json',
    'data/gcp_event.json',
    'data/keepalives.txt',
    'data/rootcheck.txt',
    'data/syscollector.py',
    'data/winevt.py',
    'data/sslmanager.key',
    'data/sslmanager.cert',
    'tools/macos_log/log_generator.m',
    'qa_docs/schema.yaml',
    'qa_docs/VERSION.json',
    'qa_docs/dockerfiles/*',
    'qa_ctl/deployment/dockerfiles/*',
    'qa_ctl/deployment/dockerfiles/qa_ctl/*',
    'qa_ctl/deployment/vagrantfile_template.txt',
    'qa_ctl/provisioning/wazuh_deployment/templates/preloaded_vars.conf.j2',
    'data/qactl_conf_validator_schema.json',
    'data/all_disabled_ossec.conf',
    'tools/migration_tool/delta_schema.json',
    'tools/migration_tool/CVE_JSON_5.0_bundled.json'
]

scripts_list = [
    'simulate-agents=wazuh_testing.scripts.simulate_agents:main',
    'wazuh-metrics=wazuh_testing.scripts.wazuh_metrics:main',
    'wazuh-report=wazuh_testing.scripts.wazuh_report:main',
    'wazuh-statistics=wazuh_testing.scripts.wazuh_statistics:main',
    'data-visualizer=wazuh_testing.scripts.data_visualizations:main',
    'simulate-api-load=wazuh_testing.scripts.simulate_api_load:main',
    'wazuh-log-metrics=wazuh_testing.scripts.wazuh_log_metrics:main',
    'qa-docs=wazuh_testing.scripts.qa_docs:main',
    'qa-ctl=wazuh_testing.scripts.qa_ctl:main',
    'check-files=wazuh_testing.scripts.check_files:main'
    'add-agents-client-keys=wazuh_testing.scripts.add_agents_client_keys:main',
    'unsync-agents=wazuh_testing.scripts.unsync_agents:main',
    'stress_results_comparator=wazuh_testing.scripts.stress_results_comparator:main'
]


def get_files_from_directory(directory):
    paths = []
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            paths.append(os.path.join('..', path, filename))
    return paths


package_data_list.extend(get_files_from_directory('wazuh_testing/qa_docs/search_ui'))

setup(
    name='wazuh_testing',
    version='4.5.0',
    description='Wazuh testing utilities to help programmers automate tests',
    url='https://github.com/wazuh',
    author='Wazuh',
    author_email='hello@wazuh.com',
    license='GPLv2',
    packages=find_packages(),
    package_data={'wazuh_testing': package_data_list},
    entry_points={'console_scripts': scripts_list},
    include_package_data=True,
    zip_safe=False
)
