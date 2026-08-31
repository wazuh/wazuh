# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""wazuh.core.manager_conf_policy: protected sections of etc/wazuh-manager.yml (api.yaml upload_configuration)."""

from copy import deepcopy

import pytest

from wazuh.core.exception import WazuhError
from wazuh.core.manager_conf_policy import check_protected_sections

CURRENT = {
    'indexer': {'hosts': ['https://127.0.0.1:9200'], 'ssl': {'certificate_authorities': [], 'certificate': '', 'key': ''}},
    'auth': {'agents': {'allow_higher_versions': False}},
    'remote': {'agents': {'allow_higher_versions': False}},
}
ALLOW_ALL = {'agents': {'allow_higher_versions': {'allow': True}}, 'indexer': {'allow': True}}
DENY_ALL = {'agents': {'allow_higher_versions': {'allow': False}}, 'indexer': {'allow': False}}


def _changed(pointer: str, value):
    document = deepcopy(CURRENT)
    node = document
    parts = pointer.strip('/').split('/')
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value
    return document


def test_unchanged_document_passes_with_every_knob():
    check_protected_sections(deepcopy(CURRENT), CURRENT, upload_configuration=DENY_ALL)
    check_protected_sections(deepcopy(CURRENT), CURRENT, upload_configuration=ALLOW_ALL)


@pytest.mark.parametrize('pointer, value, code, protected', [
    ('/indexer/hosts', ['https://10.0.0.2:9200'], 1127, '/indexer'),
    ('/indexer/ssl/certificate', 'etc/certs/other.pem', 1127, '/indexer'),
    ('/auth/agents/allow_higher_versions', True, 1129, '/auth/agents/allow_higher_versions'),
    ('/remote/agents/allow_higher_versions', True, 1129, '/remote/agents/allow_higher_versions'),
])
def test_protected_change_is_refused_when_knob_is_false(pointer, value, code, protected):
    with pytest.raises(WazuhError, match=f'.* {code} .*') as exc:
        check_protected_sections(_changed(pointer, value), CURRENT, upload_configuration=DENY_ALL)
    assert str(exc.value).endswith(protected)


@pytest.mark.parametrize('pointer, value', [
    ('/indexer/hosts', ['https://10.0.0.2:9200']),
    ('/auth/agents/allow_higher_versions', True),
    ('/remote/agents/allow_higher_versions', True),
])
def test_protected_change_is_allowed_when_knob_is_true(pointer, value):
    check_protected_sections(_changed(pointer, value), CURRENT, upload_configuration=ALLOW_ALL)


def test_indexer_knob_does_not_protect_agents_and_vice_versa():
    only_indexer = {'agents': {'allow_higher_versions': {'allow': True}}, 'indexer': {'allow': False}}
    check_protected_sections(_changed('/auth/agents/allow_higher_versions', True), CURRENT, upload_configuration=only_indexer)
    with pytest.raises(WazuhError, match='.* 1127 .*'):
        check_protected_sections(_changed('/indexer/hosts', []), CURRENT, upload_configuration=only_indexer)


def test_default_knobs_come_from_api_conf():
    from api import configuration as api_configuration
    with_deny = deepcopy(api_configuration.api_conf)
    with_deny['upload_configuration'] = DENY_ALL
    from unittest.mock import patch
    with patch('wazuh.core.manager_conf_policy.api_configuration.api_conf', new=with_deny):
        with pytest.raises(WazuhError, match='.* 1127 .*'):
            check_protected_sections(_changed('/indexer/hosts', []), CURRENT)
