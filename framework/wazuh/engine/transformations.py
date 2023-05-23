# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Any, Dict, List, Type

from wazuh.core.exception import WazuhError


class ResponseTransformations:
    """Base class for response transformations."""

    def apply_transformation(self, data):
        """Apply the transformation to the given data.

        Args:
            data: The data to be transformed.

        Raises:
            NotImplementedError: This method must be implemented in the derived classes.
        """
        raise NotImplementedError

    @staticmethod
    def can_i_run(params: Dict[str, Any], data: Any) -> bool:
        """Check if the transformation can be applied to the given parameters and data.

        Args:
            params: The parameters used for the transformation.
            data: The data to be transformed.

        Returns:
            bool: True if the transformation can be applied, False otherwise.

        Raises:
            NotImplementedError: This method must be implemented in the derived classes.
        """
        raise NotImplementedError


class EngineFieldSelector(ResponseTransformations):
    """Transformation to select specific fields from the data."""

    def __init__(self, params: Dict[str, Any]):
        self.select = params['select']

    @staticmethod
    def can_i_run(params: Dict[str, Any], data: Any) -> bool:
        if 'select' in params and params['select']:
            return True
        return False

    def apply_transformation(self, data: Dict[str, Any] or List[Dict[str, Any]]):
        """Apply the field selection transformation to the data.

        Args:
            data: The data to be transformed.

        Returns:
            The transformed data.

        Note:
            If the data is a list of dictionaries, the transformation is applied to each dictionary.
            If the data is a single dictionary, the transformation is applied to the dictionary.
        """
        transformed_data = [] if isinstance(data, list) else {}
        selected_fields = [name.strip() for name in self.select.split(",")]

        if isinstance(data, list):
            for element in data:
                selected_element = {}
                for name in selected_fields:
                    value = self._get_nested_value_select(element, name)
                    if value is not None:
                        selected_element[name] = value
                transformed_data.append(selected_element)
        else:
            for name in selected_fields:
                value = self._get_nested_value_select(data, name)
                if value is not None:
                    transformed_data[name] = value

        return transformed_data

    @staticmethod
    def _get_nested_value_select(obj: Dict[str, Any], field: str) -> Any:
        """Get the nested value from a dictionary based on the field name.

        Args:
            obj: The dictionary to search for the nested value.
            field: The field name, which may contain nested fields separated by '.'

        Returns:
            The nested value if found, None otherwise.
        """
        parts = field.split(".")
        for part in parts:
            if isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return None
        return obj


class EngineFieldSearch(ResponseTransformations):
    """Transformation to search for elements containing a specific string."""

    def __init__(self, params: Dict[str, Any]):
        self.search = params['search']

    @staticmethod
    def can_i_run(params: Dict[str, Any], data: Any) -> bool:
        if 'search' in params and params['search']:
            return True
        return False

    def apply_transformation(self, data: Dict[str, Any] or List[Dict[str, Any]]):
        """Apply the field search transformation to the data.

        Args:
            data: The data to be transformed.

        Returns:
            The transformed data.

        Note:
            If the data is a list of dictionaries, the transformation is applied to each dictionary.
            If the data is a single dictionary, the transformation is applied to the dictionary.
        """
        transformed_data = [] if isinstance(data, list) else {}

        if isinstance(data, list):
            for element in data:
                if self.search.startswith('-'):
                    complementary_string = self.search[1:]
                    if not any(complementary_string in value for value in element.values()):
                        transformed_data.append(element)
                else:
                    if any(self.search in value for value in element.values()):
                        transformed_data.append(element)
        else:
            if self.search.startswith('-'):
                complementary_string = self.search[1:]
                transformed_data = {key: value for key, value in data.items() if complementary_string not in value}
            else:
                transformed_data = {key: value for key, value in data.items() if self.search in value}

        return transformed_data


class EngineFieldOffset(ResponseTransformations):
    """Transformation to select a subset of elements from a list based on an offset."""

    def __init__(self, params: Dict[str, Any]):
        self.validate_offset(params['offset'])

        self.offset = params['offset']

    @staticmethod
    def can_i_run(params: Dict[str, Any], data: Any) -> bool:
        if 'offset' in params and params['offset'] and isinstance(data, list):
            return True
        return False

    @staticmethod
    def validate_offset(offset: int):
        """Validate the offset value.

        Args:
            offset: The offset value.

        Raises:
            WazuhError: If the offset value is less than 0.
        """
        if offset < 0:
            raise WazuhError(1400)

    def apply_transformation(self, data: List[Dict[str, Any]]):
        """Apply the offset transformation to the data.

        Args:
            data: The data to be transformed.

        Returns:
            The transformed data.

        Note:
            The transformation is applied to a list of dictionaries.
        """
        return data[self.offset:]


class EngineFieldLimit(ResponseTransformations):
    """Transformation to limit the number of elements in a list."""

    def __init__(self, params: Dict[str, Any]):
        self.validate_limit(params['limit'])

        self.limit = params['limit']

    @staticmethod
    def can_i_run(params: Dict[str, Any], data: Any) -> bool:
        if 'limit' in params and params['limit'] and isinstance(data, list):
            return True
        return False

    @staticmethod
    def validate_limit(limit: int):
        """Validate the limit value.

        Args:
            limit: The limit value.
        """
        if limit < 1:
            raise WazuhError(1401)

    def apply_transformation(self, data):
        """Apply the limit transformation to the data.

        Args:
            data: The data to be transformed.

        Returns:
            The transformed data.

        Note:
            The transformation is applied to a list of dictionaries.
        """
        real_limit = self.limit
        if self.limit >= len(data):
            real_limit = len(data)

        return data[:real_limit]


class EngineFieldSort(ResponseTransformations):
    """Transformation to sort a list of dictionaries based on a field or fields."""

    def __init__(self, params: Dict[str, Any]):
        self.sort = params['sort']

    @staticmethod
    def can_i_run(params: Dict[str, Any], data: Any) -> bool:
        if 'sort' in params and params['sort'] and isinstance(data, list):
            return True
        return False

    def apply_transformation(self, data: List[Dict[str, Any]]):
        """Apply the sort transformation to the data.

        Args:
            data: The data to be transformed.

        Returns:
            The transformed data.

        Note:
            The transformation is applied to a list of dictionaries.
        """
        # TODO IMPLEMENT
        return data


class EngineTransformationSequence:
    """Sequence of response transformations."""

    def __init__(self, transformations: List[Type[ResponseTransformations]]):
        self.transformations = transformations

    def apply_sequence(self, params: Dict[str, Any], data: Any) -> Any:
        """Apply the sequence of transformations to the data.

        Args:
            params: The parameters used for the transformations.
            data: The data to be transformed.

        Returns:
            The transformed data.

        Note:
            The transformations are applied in the order specified in the sequence.
        """
        transformed_data = data
        for transformation in self.transformations:
            if transformation.can_i_run(params=params, data=data):
                transformed_data = transformation(params=params).apply_transformation(transformed_data)

        return transformed_data

    @classmethod
    def default_sequence(cls):
        """Create a default sequence of transformations.

        Returns:
            An instance of EngineTransformationSequence with the default transformations.
        """
        list_of_transformations = [
            EngineFieldSearch, EngineFieldSelector,
            EngineFieldOffset, EngineFieldLimit, EngineFieldSort]

        return cls(list_of_transformations)
