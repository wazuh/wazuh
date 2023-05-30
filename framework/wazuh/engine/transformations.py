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
        # Create an empty list if the data is a list, otherwise create an empty dictionary
        transformed_data = [] if isinstance(data, list) else {}

        # Remove leading/trailing spaces and split the selected fields based on comma separation
        selected_fields = [name.strip() for name in self.select.split(",")]

        if isinstance(data, list):
            # If the data is a list, iterate over each element
            for element in data:
                selected_elements = self._select_fields(selected_fields, element)
                transformed_data.append(selected_elements)
        else:
            transformed_data = self._select_fields(selected_fields, data)

        # Return the transformed data
        return transformed_data

    @staticmethod
    def _select_fields(selected_fields: List[str], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Selects and extracts specified fields from the given data dictionary.

        Args:
            selected_fields (List[str]): A list of field names to be selected.
            data (Dict[str, Any]): The data dictionary to select fields from.

        Returns:
            Dict[str, Any]: A dictionary containing the selected fields and their values.

        Example:
            selected_fields = ['name', 'age', 'address.city']
            data = {'name': 'John', 'age': 25, 'address': {'street': '123 Main St', 'city': 'New York'}}
            result = MyClass._select_fields(selected_fields, data)
            print(result)
            # Output: {'name': 'John', 'age': 25, 'address': {'city': 'New York'}}
        """

        # Create an empty dictionary to store the selected fields for the current element
        selected_element = {}
        for name in selected_fields:
            # Get the value of the selected field for the current element
            value = EngineFieldSelector._get_nested_value_select(data, name)

            if value is not None:
                # Split the field into nested fields based on dot separation
                nested_fields = name.split('.')

                # Traverse the nested fields, creating dictionaries as necessary
                current_dict = selected_element
                for field in nested_fields[:-1]:
                    current_dict = current_dict.setdefault(field, {})

                # Assign the value to the final nested field
                current_dict[nested_fields[-1]] = value

        return selected_element

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
        if 'search' in params and params['search'] and isinstance(data, list):
            return True
        return False

    def apply_transformation(self, data: List[Dict[str, Any]]):
        """Apply the field search transformation to the data.

        Args:
            data: The data to be transformed.

        Returns:
            The transformed data.

        Note:
            If the data is a list of dictionaries, the transformation is applied to each dictionary.
            If the data is a single dictionary, the transformation is applied to the dictionary.
        """
        transformed_data = []

        if isinstance(data, list):
            # If the data is a list of dictionaries, apply transformation to each dictionary
            for element in data:
                if self.search.startswith('-'):
                    # If search starts with '-', check for absence of complementary string in any value
                    complementary_string = self.search[1:]
                    if not any(complementary_string in value for value in element.values()):
                        transformed_data.append(element)
                else:
                    # Otherwise, check for presence of search string in any value
                    if any(self.search in value for value in element.values()):
                        transformed_data.append(element)

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


def sorting_lambda(filters: List[Dict[str, Any]], data: Dict[str, Any]) -> tuple:
    """
    Sorts data based on the provided filters and returns a tuple of sorted values.

    Args:
        filters (List[Dict[str, Any]]): A list of filter dictionaries specifying the fields and sorting options.
            Each filter dictionary should have the following keys:
                - 'fields' (List[str]): A list of strings representing the fields to filter and sort by.
                - 'reverse' (bool): A boolean value indicating whether to sort in reverse order.
        data (Dict[str, Any]): A dictionary containing the data to be filtered and sorted.

    Returns:
        tuple: A tuple containing the sorted values based on the filters.

    Example:
        filters = [{'fields': ['name'], 'reverse': False}, {'fields': ['age'], 'reverse': True}]
        data = {'name': 'John', 'age': 25}
        result = sorting_lambda(filters, data)
        print(result)  # Output: ('John', -25)
    """

    final_tuple = []

    for filter_dict in filters:
        value_of_filter = data
        for key in filter_dict['fields']:
            value_of_filter = value_of_filter.get(key)
        print(value_of_filter)  # Print the value obtained from filtering

        result = value_of_filter
        if value_of_filter is not None:
            if isinstance(value_of_filter, int):
                result = value_of_filter
            elif isinstance(value_of_filter, str):
                result = ord(value_of_filter)  # Convert string to ASCII value

            if filter_dict['reverse']:
                result = -result  # Reverse the sorting order

        final_tuple.append(result)

    return tuple(final_tuple)


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
        # Split the sort string by commas to get individual sorting fields
        filters: List[str] = self.sort.split(',')

        # Create a list to store the sorting criteria
        list_of_sort = []

        # Iterate over each sorting field
        for field in filters:
            # Check if the sorting order is reverse (indicated by '-' prefix)
            reverse = True if field[0] == '-' else False

            # Remove the prefix if present
            if field[0] == '+' or field[0] == '-':
                field = field[1:]

            # Split the field by dot to handle nested fields
            nested_fields = field.split('.')

            # Add the sorting criteria to the list
            list_of_sort.append({'reverse': reverse, 'fields': nested_fields})

        # Sort the data using the sorting criteria and the sorting_lambda function as the key
        result = sorted(data, key=lambda x: sorting_lambda(list_of_sort, x))
        return result


class EngineFieldQuery(ResponseTransformations):
    """Class for applying field-based queries to data."""

    def __init__(self, params: Dict[str, Any]):
        """
        Initialize the EngineFieldQuery instance.

        Args:
            params: A dictionary containing the query parameters.
                - 'q': The query string to filter results by.

        Raises:
            KeyError: If 'q' is not present in the params dictionary.
        """
        self._validate_query_value(params['q'])
        self.q = params['q']

    @staticmethod
    def _validate_query_value(query: str):
        # If there is no "=" inside the string, the query string is invalid
        for field in query.split(','):
            split_field = field.split('=')

            if len(split_field) != 2 or any([value == '' for value in split_field]):
                raise WazuhError(1407)

    @staticmethod
    def can_i_run(params: Dict[str, Any], data: Any) -> bool:
        """
        Check if the field-based query transformation can be applied.

        The transformation can be applied if the following conditions are met:
        - 'q' key is present in the params dictionary.
        - 'q' value is not empty.
        - The data is of type list.

        Args:
            params: A dictionary containing the query parameters.
            data: The data to be transformed.

        Returns:
            bool: True if the transformation can be applied, False otherwise.
        """
        if 'q' in params and params['q'] and isinstance(data, list):
            return True
        return False

    @staticmethod
    def _separate_key_and_value(query_field: str) -> Dict[str, Any]:
        """
        Separate the key and value from a query field.

        Args:
            query_field: A string representing a query field in the format "key=value".

        Returns:
            dict: A dictionary containing the separated key and value.
                - 'key': The key extracted from the query field.
                - 'value': The value extracted from the query field.

        Raises:
            WazuhError: If the query field is invalid (does not contain '=').
        """
        split_value = query_field.split('=')

        return {'key': split_value[0], 'value': split_value[1]}

    def apply_transformation(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Apply the field-based query transformation to the given data.

        Args:
            data: A list of dictionaries representing the data to be transformed.

        Returns:
            list: A filtered list of dictionaries containing only the entries that satisfy the query conditions.
        """
        query_fields = [self._separate_key_and_value(query) for query in self.q.split(',')]
        selected_data = filter(
            lambda x: all(
                query['key'] in x and str(x.get(query['key'])) == query['value']
                for query in query_fields
            ),
            data
        )
        return list(selected_data)


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
