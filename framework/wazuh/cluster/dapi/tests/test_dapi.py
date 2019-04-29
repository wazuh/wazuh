import json
import pytest

from wazuh import Wazuh
from wazuh.agent import Agent
from wazuh.exception import WazuhError, WazuhInternalError
from wazuh.manager import status
from wazuh.results import WazuhResult, WazuhQueryResult
from wazuh.cluster.dapi.dapi import WazuhJSONEncoder, as_wazuh_object

objects_to_encode = [
    {'foo': 'bar',
     'foo2': 3,
     'mycallable': Wazuh(ossec_path='/var/ossec').get_ossec_init},
    {'foo': 'bar',
     'foo2': 3,
     'mycallable': Agent.get_agents_summary},
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
     'result': WazuhQueryResult({'field1': 'value1', 'field2': 3}, str_priority=['KO', 'OK'])}
]


@pytest.mark.parametrize('obj', objects_to_encode)
def test_encoder_decoder(obj):

    # Encoding first object
    encoded = json.dumps(obj, cls=WazuhJSONEncoder)

    # Decoding first object
    obj_again = json.loads(encoded, object_hook=as_wazuh_object)
    assert(obj_again == obj)
