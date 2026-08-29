# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""api/test/integration/env/tools/yaml_merge.py: the helper the integration environment uses to edit etc/wazuh-manager.yml."""

import importlib.util
import os

import yaml

TOOL = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'test', 'integration', 'env', 'tools',
                    'yaml_merge.py')

spec = importlib.util.spec_from_file_location('yaml_merge', TOOL)
yaml_merge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(yaml_merge)


def test_deep_merge_replaces_scalars_and_lists_and_merges_mappings():
    target = {'cluster': {'name': 'wazuh', 'nodes': ['127.0.0.1'], 'port': 1516}, 'logging': {'log_format': ['plain']}}
    fragment = {'cluster': {'nodes': ['wazuh-master'], 'hidden': False}, 'auth': {'use_source_ip': False}}

    yaml_merge.deep_merge(target, fragment)

    assert target == {'cluster': {'name': 'wazuh', 'nodes': ['wazuh-master'], 'port': 1516, 'hidden': False},
                      'logging': {'log_format': ['plain']}, 'auth': {'use_source_ip': False}}


def test_set_option_creates_intermediate_mappings():
    document = {'cluster': {'name': 'wazuh'}}

    yaml_merge.set_option(document, 'cluster.node_type', 'worker')
    yaml_merge.set_option(document, 'remote.legacy.local_ip', '0.0.0.0')

    assert document == {'cluster': {'name': 'wazuh', 'node_type': 'worker'}, 'remote': {'legacy': {'local_ip': '0.0.0.0'}}}


def test_main_merge_and_set_round_trip(tmp_path):
    target = tmp_path / 'wazuh-manager.yml'
    target.write_text('cluster:\n  name: wazuh\n  nodes:\n    - 127.0.0.1\n')
    fragment = tmp_path / 'fragment.yml'
    fragment.write_text('vulnerability-detection:\n  enabled: false\n')

    yaml_merge.main(['yaml_merge.py', 'merge', str(target), str(fragment)])
    yaml_merge.main(['yaml_merge.py', 'set', str(target), 'cluster.nodes', '[wazuh-master]'])
    yaml_merge.main(['yaml_merge.py', 'set', str(target), 'cluster.key', '9d273b53510fef702b54a92e9cffc82e'])

    assert yaml.safe_load(target.read_text()) == {
        'cluster': {'name': 'wazuh', 'nodes': ['wazuh-master'], 'key': '9d273b53510fef702b54a92e9cffc82e'},
        'vulnerability-detection': {'enabled': False},
    }
