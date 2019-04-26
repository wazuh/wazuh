
from api.models.basic_info import BasicInfo


def test_model_basic_info():

    mock = {
        'title': 'title',
        'api_version': 'api_version',
        'revision': 1000,
        'license_name': 'license_name',
        'license_url': 'license_url',
        'hostname': 'hostname',
        'timestamp': 'timestamp'
    }

    obj = BasicInfo(**mock)
    assert obj == BasicInfo.from_dict(mock)
    assert mock == obj.to_dict()
