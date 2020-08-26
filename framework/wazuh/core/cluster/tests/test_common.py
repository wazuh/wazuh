import json
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.common.getgrnam'):
    with patch('wazuh.common.getpwnam'):
        with patch('wazuh.common.ossec_uid'):
            with patch('wazuh.common.ossec_gid'):
                sys.modules['wazuh.rbac.orm'] = MagicMock()

                from wazuh.core.cluster.cluster import get_node
                from wazuh.agent import get_agents_summary_status
                from wazuh.core.exception import WazuhError, WazuhInternalError
                from wazuh.core.manager import status
                from wazuh.core.results import WazuhResult, AffectedItemsWazuhResult
                from wazuh.core.cluster.common import WazuhJSONEncoder, as_wazuh_object

affected = AffectedItemsWazuhResult(dikt={'data': ['test']}, affected_items=['001', '002'])
affected.add_failed_item(id_='099', error=WazuhError(code=1750, extra_message='wiiiiiii'))
affected.add_failed_item(id_='111', error=WazuhError(code=1750, extra_message='weeeeee'))
affected.add_failed_item(id_='555', error=WazuhError(code=1750, extra_message='wiiiiiii'))
affected.add_failed_item(id_='333', error=WazuhError(code=1707, extra_message='wiiiiiii'))

with patch('wazuh.common.ossec_path', new=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')):
    objects_to_encode = [
        {'foo': 'bar',
         'foo2': 3,
         'mycallable': get_node},
        {'foo': 'bar',
         'foo2': 3,
         'mycallable': get_agents_summary_status},
        {'foo': 'bar',
         'foo2': 3,
         'mycallable': status},
        {'foo': 'bar',
         'foo2': 3,
         'exception': WazuhError(1500,
                                 extra_message="test message",
                                 extra_remediation="test remediation")},
        {'foo': 'bar',
         'foo2': 3,
         'exception': WazuhInternalError(1000,
                                         extra_message="test message",
                                         extra_remediation="test remediation")},
        {'foo': 'bar',
         'foo2': 3,
         'result': WazuhResult({'field1': 'value1', 'field2': 3}, str_priority=['KO', 'OK'])},
        {'foo': 'bar',
         'foo2': 3,
         'result': affected}
    ]


@pytest.mark.parametrize('obj', objects_to_encode)
@patch('wazuh.common.ossec_path', new=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data'))
def test_encoder_decoder(obj):
    # Encoding first object
    encoded = json.dumps(obj, cls=WazuhJSONEncoder)

    # Decoding first object
    obj_again = json.loads(encoded, object_hook=as_wazuh_object)
    assert (obj_again == obj)
