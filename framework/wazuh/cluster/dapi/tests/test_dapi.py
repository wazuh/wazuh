import json

from wazuh import Wazuh
from wazuh.agent import Agent
from wazuh.manager import status
from wazuh.cluster.dapi.dapi import WazuhJSONEncoder, as_wazuh_object

obj_to_encode_1 = {'foo': 'bar',
                   'foo2': 3,
                   'mycallable': Wazuh(ossec_path='/var/ossec').get_ossec_init
                   }

obj_to_encode_2 = {'foo': 'bar',
                   'foo2': 3,
                   'mycallable': Agent.get_agents_summary
                   }

obj_to_encode_3 = {'foo': 'bar',
                   'foo2': 3,
                   'mycallable': status
                   }


def test_encoder_decoder():

    # Encoding first object
    encoded = json.dumps(obj_to_encode_1, cls=WazuhJSONEncoder)
    encoded_dict = json.loads(encoded)
    assert(isinstance(encoded_dict, dict))
    assert('mycallable' in encoded_dict)
    mycallable_dict = encoded_dict['mycallable']
    assert('__callable__' in mycallable_dict)
    callable = mycallable_dict['__callable__']
    assert('__wazuh__' in callable)
    assert ('__name__' in callable)
    assert ('__qualname__' in callable)
    assert ('__module__' in callable)

    # Decoding first object
    obj_1_again = json.loads(encoded, object_hook=as_wazuh_object)
    assert(obj_1_again == obj_to_encode_1)

    # Encoding second object
    encoded = json.dumps(obj_to_encode_2, cls=WazuhJSONEncoder)
    encoded_dict = json.loads(encoded)
    assert (isinstance(encoded_dict, dict))
    assert ('mycallable' in encoded_dict)
    mycallable_dict = encoded_dict['mycallable']
    assert ('__callable__' in mycallable_dict)
    callable = mycallable_dict['__callable__']
    assert ('__name__' in callable)
    assert ('__qualname__' in callable)
    assert ('__module__' in callable)

    # Decoding second object
    obj_2_again = json.loads(encoded, object_hook=as_wazuh_object)
    assert(obj_2_again == obj_to_encode_2)

    # Encoding third object
    encoded = json.dumps(obj_to_encode_3, cls=WazuhJSONEncoder)
    encoded_dict = json.loads(encoded)
    assert (isinstance(encoded_dict, dict))
    assert ('mycallable' in encoded_dict)
    mycallable_dict = encoded_dict['mycallable']
    assert ('__callable__' in mycallable_dict)
    callable = mycallable_dict['__callable__']
    assert ('__name__' in callable)
    assert ('__qualname__' in callable)
    assert ('__module__' in callable)

    # Decoding third object
    obj_3_again = json.loads(encoded, object_hook=as_wazuh_object)
    assert(obj_3_again == obj_to_encode_3)



