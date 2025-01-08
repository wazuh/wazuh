# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import importlib.util
import inspect
import sys
from json import JSONDecodeError
from os import listdir
from os.path import abspath, dirname, join
from unittest.mock import MagicMock, patch

import pytest
from connexion import ProblemException

from api.controllers.util import JSON_CONTENT_TYPE
from api.models import agent_registration_model

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['api.authentication'] = MagicMock()
        from wazuh import WazuhError

        from api.models import agent_registration_model
        from api.models import base_model_ as bm
        from api.util import deserialize_model

        del sys.modules['api.authentication']

models_path = dirname(dirname(abspath(__file__)))


class TestModel(bm.Body):
    """Test class for custom Model. Body inherits from Model and has all the attributes required for testing."""

    __test__ = False

    def __init__(self, *args):
        self.swagger_types = {f'arg_{i + 1}': type(arg) for i, arg in enumerate(args)}

        if not self.swagger_types:
            self.swagger_types = {'arg_1': str}
            args = ('value1',)

        self.attribute_map = {arg: arg for arg in self.swagger_types}

        for arg, value in zip(self.swagger_types.keys(), args):
            setattr(self, arg, value)


class RequestMock:
    """Class Request mock."""

    def __init__(self, content_type):
        self._content_type = content_type

    @property
    def mimetype(self):
        return self._content_type


class ToDictObject:
    def __init__(self, value):
        self.value = value

    def to_dict(self):
        return {'value': self.value}

    def __repr__(self):
        return self.to_dict()

    def __eq__(self, other):
        return other == self.to_dict()


def test_model_from_dict():
    """Test class Model `from_dict` method."""
    exc = WazuhError(1000)
    with pytest.raises(exc.__class__):
        bm.Model.from_dict(exc)

    dikt = {'test_key': 'test_value'}
    assert bm.Model.from_dict(dikt) == deserialize_model(dikt, bm.Model)


def test_model_to_dict():
    """Test class Model `to_dict` method."""
    model_params = ('value1', 2, [3, {'key3': 'value3'}], {'key1': 'value_dict_1'}, ToDictObject(999))
    test_model = TestModel(*model_params)
    dikt = test_model.to_dict()
    assert isinstance(dikt, dict)
    assert dikt == {f'arg_{i + 1}': value for i, value in enumerate(model_params)}


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
    not_equal_model = TestModel('test')

    # Operator == (__eq__)
    assert test_model == equal_model
    with pytest.raises(AssertionError):
        assert test_model == not_equal_model

    # Operator != (__ne__)
    assert test_model != not_equal_model
    with pytest.raises(AssertionError):
        assert test_model != equal_model


def test_allof():
    model1 = TestModel('a', 1)
    model2 = TestModel('a', 2)

    allof = bm.AllOf(model1, model2)
    assert allof.models == (model1, model2)


def test_allof_to_dict():
    """Test class AllOf class `to_dict` method."""
    args1 = ('one', 1)
    args2 = ('two', 2)

    allof = bm.AllOf(TestModel(*args1), TestModel(*args2))
    # Same model means that the second model values will overwrite the first
    assert tuple(allof.to_dict().values()) == args2

    allof = bm.AllOf(TestModel(*args2), TestModel(*args1))
    assert tuple(allof.to_dict().values()) == args1


def test_data():
    """Test class Data."""
    model = TestModel('one', 1)
    data_model = bm.Data(model)

    assert data_model.swagger_types == {'data': bm.Model}
    assert data_model.attribute_map == {'data': 'data'}
    assert data_model._data == model

    # Test class properties
    new_data = {'new': 'data'}
    data_model.data = new_data
    assert data_model.data == new_data


def test_data_from_dict():
    """Test class Data `from_dict` class method."""
    test_dict = {'test_key': 'test_value'}
    assert bm.Data.from_dict(test_dict) == deserialize_model(test_dict, bm.Data)


def test_items():
    """Test class Items."""
    list = [TestModel('one', 2)]
    items_model = bm.Items(list)

    assert items_model.swagger_types == {'items': bm.List[bm.Model]}
    assert items_model.attribute_map == {'items': 'items'}
    assert items_model._items == list

    # Test class properties
    new_items = [TestModel('new', 9)]
    items_model.items = new_items
    assert items_model.items == new_items


def test_items_from_dict():
    """Test class Items `from_dict` class method."""
    test_dict_list = [{'test_key': 'test_value'}, {'test_key2': 'test_value2'}]
    assert bm.Items.from_dict(test_dict_list) == deserialize_model(test_dict_list, bm.Items)


@pytest.mark.asyncio
@pytest.mark.parametrize('additional_kwargs', [{}, {'arg_2': 'test'}])
async def test_body_get_kwargs(additional_kwargs):
    """Test class Body `get_kwargs` class method."""
    request = {'arg_1': 'value1'}
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


def test_body_from_dict():
    """Test class Body `from_dict` method."""
    test_dict = {'test_key1': 'test_value1', 'test_key2': [{'test_key21': 'test_value21'}]}
    assert bm.Body.from_dict(test_dict) == deserialize_model(test_dict, bm.Body)


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
    content_type = JSON_CONTENT_TYPE
    request = RequestMock(content_type)

    TestModel.validate_content_type(request, content_type)


def test_body_validate_content_type_ko():
    """Test class Body `validate_content_type` method exceptions."""
    request = RequestMock(JSON_CONTENT_TYPE)

    with pytest.raises(ProblemException) as exc:
        TestModel.validate_content_type(request, 'application/xml')

    assert exc.value.ext['code'] == 6002


@pytest.mark.parametrize('module_name', [module for module in listdir(models_path) if module.endswith('model.py')])
@patch('api.util.deserialize_model')
def test_all_models(deserialize_mock, module_name):
    """Test that all API models classes are correctly defined."""
    # Load API model
    spec = importlib.util.spec_from_file_location('test_module', join(models_path, module_name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # Get all defined classes
    for module_classes in inspect.getmembers(module, inspect.isclass):
        for module_class in module_classes[1:]:
            if module_class.__module__ == 'test_module':
                # Check if they can be defined
                instance = module_class()
                for p in [p for p in module_class.__dict__ if not p.startswith('__')]:
                    # Assert that all its attributes have defined properties (getter and setter)
                    value = ''
                    if module_class.__name__ == 'AgentRegistrationModel' and p == 'key':
                        value = '7b8276c3bf96aff5709346d368f04aed'
                    else:
                        value = 'test'

                    setattr(instance, p, value)
                    assert getattr(instance, p) == value

                # Test the only possible overwritten method: `from_dict`
                getattr(module_class, 'from_dict')('test')
                deserialize_mock.assert_called_with('test', module_class)


@pytest.mark.parametrize('key', ('7b8276c3bf96aff5709346d368f04aed', 'test', '7b8276c3bf96aff5709346d368f04aedA'))
async def test_agent_registration_model_validation(key):
    request = {
        'id': '01929571-49b5-75e8-a3f6-1d2b84f4f71a',
        'name': 'testing',
        'key': key,
        'type': 'endpoint',
        'version': '5.0.0',
    }

    if len(key) != agent_registration_model.KEY_LENGTH:
        with pytest.raises(ProblemException) as exc:
            await agent_registration_model.AgentRegistrationModel.get_kwargs(request)

        assert exc.value.title == 'Invalid key length'
        assert exc.value.detail == 'The key must be 32 characters long'
    else:
        await agent_registration_model.AgentRegistrationModel.get_kwargs(request)
