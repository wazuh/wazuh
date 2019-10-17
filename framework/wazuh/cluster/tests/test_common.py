import json
import pytest
from unittest.mock import patch
with patch('wazuh.common.getgrnam'):
    with patch('wazuh.common.getpwnam'):

        from wazuh import Wazuh
        from wazuh.agent import get_agents_summary_status
        from wazuh.exception import WazuhError, WazuhInternalError
        from wazuh.manager import status
        from wazuh.results import WazuhResult, AffectedItemsWazuhResult
        from wazuh.cluster.common import WazuhJSONEncoder, as_wazuh_object


affected = AffectedItemsWazuhResult(dikt={'data': ['test']}, affected_items=['001', '002'])
affected.add_failed_item(id_='099', error=WazuhError(code=1750, extra_message='wiiiiiii'))
affected.add_failed_item(id_='111', error=WazuhError(code=1750, extra_message='weeeeee'))
affected.add_failed_item(id_='555', error=WazuhError(code=1750, extra_message='wiiiiiii'))
affected.add_failed_item(id_='333', error=WazuhError(code=1707, extra_message='wiiiiiii'))


objects_to_encode = [
    {'foo': 'bar',
     'foo2': 3,
     'mycallable': Wazuh().to_dict},
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
def test_encoder_decoder(obj):

    # Encoding first object
    encoded = json.dumps(obj, cls=WazuhJSONEncoder)

    # Decoding first object
    obj_again = json.loads(encoded, object_hook=as_wazuh_object)
    assert(obj_again == obj)
