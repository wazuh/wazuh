# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import sys
from json import JSONDecodeError
from unittest.mock import patch, MagicMock

import pytest
from connexion import ProblemException

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['api.authentication'] = MagicMock()
        from api.models import base_model_ as bm
        from wazuh import WazuhError
        from api.util import deserialize_model

        del sys.modules['api.authentication']


class TestModel(bm.Body):
    """Test class for custom Model. Body inherits from Model and has all the attributes required for testing."""

    def __init__(self, arg_1: str = None, arg_2: int = None):
        self.swagger_types = {
            'arg_1': str,
            'arg_2': int
        }

        self.attribute_map = {
            'arg_1': 'arg_1',
            'arg_2': 'arg_2'
        }

        self._arg_1 = arg_1
        self._arg_2 = arg_2

    @property
    def arg_1(self):
        return self._arg_1

    @arg_1.setter
    def arg_1(self, arg_1):
        self._arg_1 = arg_1

    @property
    def arg_2(self):
        return self._arg_2

    @arg_2.setter
    def arg_2(self, arg_2):
        self._arg_2 = arg_2


class RequestMock:
    """Class Request mock."""
    def __init__(self, content_type):
        self._content_type = content_type

    @property
    def content_type(self):
        return self._content_type


def test_model_from_dict():
    """Test class Model `from_dict` method."""
    exc = WazuhError(1000)
    with pytest.raises(exc.__class__):
        bm.Model.from_dict(exc)

    dikt = {'test_key': 'test_value'}
    assert bm.Model.from_dict(dikt) == deserialize_model(dikt, bm.Model)


def test_model_to_dict():
    """Test class Model `to_dict` method."""
    test_model = TestModel('value1', 2)
    dikt = test_model.to_dict()
    assert isinstance(dikt, dict)
    assert dikt == {'arg_1': 'value1', 'arg_2': 2}


def test_model_to_str():
    """Test class Model `to_str` method."""
    test_model = TestModel('value1', 2)
    dikt = test_model.to_dict()
    str_dikt = test_model.to_str()
    assert isinstance(str_dikt, str)
    assert str_dikt == str(dikt)


def test_model_operator_overloading():
    """Test class Model multiple operator overloading."""
    original_dict = {'arg_1': 'value1', 'arg_2': 2}
    test_model = TestModel(*list(original_dict.values()))

    # Operator __repr__ (for print)
    # Assert that we can print a Model right away
    print(test_model)

    equal_model = TestModel(*list(original_dict.values()))
    not_equal_model = TestModel()

    # Operator == (__eq__)
    assert test_model == equal_model
    with pytest.raises(AssertionError):
        assert test_model == not_equal_model

    # Operator != (__ne__)
    assert test_model != not_equal_model
    with pytest.raises(AssertionError):
        assert test_model != equal_model


def test_model_properties():
    """Test setters and getters (properties) from class Model."""
    test_model = TestModel()
    value = 'test'

    assert test_model.arg_1 is None
    test_model.arg_1 = value
    assert test_model.arg_1 == value


@pytest.mark.asyncio
@pytest.mark.parametrize('additional_kwargs', [
    {},
    {'additional': 'test'}
])
async def test_body_get_kwargs(additional_kwargs):
    """Test class Body `get_kwargs` class method."""
    request = {'arg_1': 'value1'}  # Missing arg_2
    test_model = TestModel(*list(request.values()))

    kwargs = await TestModel.get_kwargs(request, additional_kwargs=additional_kwargs)
    request.update(additional_kwargs)
    try:
        assert kwargs == test_model.to_dict()
    except AssertionError:
        # Check for additional_kwargs
        assert set(kwargs) - set(test_model.to_dict()) == set(additional_kwargs)


@pytest.mark.asyncio
async def test_body_get_kwargs_ko():
    """Test class Body `get_kwargs` class method exceptions."""
    invalid_request = {'invalid': 'value1'}
    with patch('api.models.base_model_.util.deserialize_model', side_effect=JSONDecodeError('msg', 'a', 1)):
        with pytest.raises(ProblemException) as exc:
            await TestModel.get_kwargs(invalid_request)

        assert exc.value.ext['code'] == 1018

    with pytest.raises(ProblemException) as exc:
        await TestModel.get_kwargs(invalid_request)

    # Custom exception. Very specific detail
    assert 'Invalid field found' in exc.value.detail


def test_body_decode_body():
    """Test class Body `decode_body` class method."""
    body = 'body'
    assert TestModel.decode_body(body.encode()) == body


def test_body_decode_body_ko():
    """Test class Body `decode_body` class method exceptions."""
    # UnicodeDecodeError
    with pytest.raises(ProblemException) as exc:
        TestModel.decode_body('test'.encode('utf-16'), unicode_error=1911)

    assert exc.value.ext['code'] == 1911

    # AttributeError
    with pytest.raises(ProblemException) as exc:
        TestModel.decode_body('test', attribute_error=1912)

    assert exc.value.ext['code'] == 1912


def test_body_validate_content_type():
    """Test class Body `validate_content_type` method."""
    content_type = 'application/json'
    request = RequestMock(content_type)

    TestModel.validate_content_type(request, content_type)


def test_body_validate_content_type_ko():
    """Test class Body `validate_content_type` method exceptions."""
    request = RequestMock('application/json')

    with pytest.raises(ProblemException) as exc:
        TestModel.validate_content_type(request, 'application/xml')

    assert exc.value.ext['code'] == 6002
