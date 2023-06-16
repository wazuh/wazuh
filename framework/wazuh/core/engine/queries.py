# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Any, Dict, List, Type, Optional

from wazuh.core.exception import WazuhError
from wazuh.core.utils import filter_array_by_query


class BaseQuery:
    """Base class for response filters."""

    def apply(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply the filter to the given data.

        Parameters
        ----------
        data:  List[Dict[str, Any]]
            The data to be filtered.

        Raises
        ------
        NotImplementedError:
            This method must be implemented in the derived classes.
        """
        raise NotImplementedError

    @staticmethod
    def should_apply(filters: Dict[str, Any], data: Any) -> bool:
        """Check if the filter can be applied to the given filters and data.

        Parameters
        ----------
        filters: Dict[str, Any]
            The filters used for the filter.
        data: Any
            The data to be filtered.

        Returns
        ----------
        bool
            True if the filter can be applied, False otherwise.

        Raises
        ----------
        NotImplementedError:
            This method must be implemented in the derived classes.
        """
        raise NotImplementedError


class FieldSelector(BaseQuery):
    """Filter to select specific fields from the data."""

    def __init__(self, params: Dict[str, Any]):
        self.select = params['select']

    @staticmethod
    def should_apply(filters: Dict[str, Any], data: Any) -> bool:
        """ Check if the filter can be applied to the given filters and data.

        Parameters
        ----------
        filters: Dict[str, Any]
            The filters used for the filter.
        data: Any
            The data to be filtered.

        Returns
        ----------
        bool
            True if the filter can be applied, False otherwise.
        """
        if 'select' in filters and filters['select'] and isinstance(data, list):
            return True
        return False

    def apply(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply the field selection filter to the data.

        Parameters
        ----------
        data:  List[Dict[str, Any]]
            The data to be filtered.

        Returns
        ----------
        List[Dict[str, Any]
            The filtered data.

        Note:
            If the data is a list of dictionaries, the filter is applied to each dictionary.
        """
        filtered_data = []

        # Remove leading/trailing spaces and split the selected fields based on comma separation
        selected_fields = [name.strip() for name in self.select.split(",")]

        # If the data is a list, iterate over each element
        for element in data:
            selected_elements = self._select_fields(selected_fields, element)
            filtered_data.append(selected_elements)

        # Return the filtered data
        return filtered_data

    def _select_fields(self, selected_fields: List[str], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Selects and extracts specified fields from the given data dictionary.

        Parameters
        ----------
        selected_fields: List[str]
            A list of field names to be selected.
        data: Dict[str, Any]
            The data dictionary to select fields from.

        Returns
        ----------
        Dict[str, Any]
            A dictionary containing the selected fields and their values.
        """

        # Create an empty dictionary to store the selected fields for the current element
        selected_element = {}
        for name in selected_fields:
            # Get the value of the selected field for the current element
            value = self._get_nested_value_select(data, name)

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

    def _get_nested_value_select(self, obj: Dict[str, Any], field: str) -> Optional[Any]:
        """Get the nested value from a dictionary based on the field name.

        Parameters
        ----------
        obj: Dict[str, Any]
            The dictionary to search for the nested value.
        field: str
            The field name, which may contain nested fields separated by '.'

        Returns
        ----------
        Optional[Any]
            The nested value if found, None otherwise.
        """
        parts = field.split(".")
        for part in parts:
            if isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                return None
        return obj


class FieldSearch(BaseQuery):
    """Filter to search for elements containing a specific string."""

    def __init__(self, params: Dict[str, Any]):
        self.search = params['search']

    @staticmethod
    def should_apply(filters: Dict[str, Any], data: Any) -> bool:
        """ Check if the filter can be applied to the given filters and data.

        Parameters
        ----------
        filters: Dict[str, Any]
            The filters used for the filter.
        data: Any
            The data to be filtered.

        Returns
        ----------
        bool
            True if the filter can be applied, False otherwise.
        """
        if 'search' in filters and filters['search'] and isinstance(data, list):
            return True
        return False

    def apply(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply the field search filter to the data.

        Parameters
        ----------
        data:  List[Dict[str, Any]]
            The data to be filtered.

        Returns
        ----------
        List[Dict[str, Any]
            The filtered data.

        Note:
            If the data is a list of dictionaries, the filter is applied to each dictionary.
        """
        filtered_data = []

        if isinstance(data, list):
            # If the data is a list of dictionaries, apply filter to each dictionary
            for element in data:
                if self.search.startswith('-'):
                    # If search starts with '-', check for absence of complementary string in any value
                    complementary_string = self.search[1:]
                    if not any(complementary_string in value for value in element.values()):
                        filtered_data.append(element)
                else:
                    # Otherwise, check for presence of search string in any value
                    if any(self.search in value for value in element.values()):
                        filtered_data.append(element)

        return filtered_data


class FieldOffsetLimit(BaseQuery):
    """Filter to select a subset of elements from a list based on an offset and limit."""

    def __init__(self, params: Dict[str, Any]):
        self._validate_offset(params['offset'])
        self._validate_limit(params['limit'])

        self.offset = params['offset']
        self.limit = params['limit']

    @staticmethod
    def should_apply(filters: Dict[str, Any], data: Any) -> bool:
        """ Check if the filter can be applied to the given filters and data.

        Parameters
        ----------
        filters: Dict[str, Any]
            The filters used for the filter.
        data: Any
            The data to be filtered.

        Returns
        ----------
        bool
            True if the filter can be applied, False otherwise.
        """
        if 'offset' in filters and filters['offset'] and 'limit' in filters and filters['limit'] and isinstance(data, list):
            return True
        return False

    @staticmethod
    def _validate_offset(offset: int):
        """Validate the offset value.

        Parameters
        ----------
        offset: int
            The offset value.

        Raises
        ----------
        WazuhError
            Raises if the offset value is less than 0.
        """
        if offset < 0:
            raise WazuhError(1400)

    @staticmethod
    def _validate_limit(limit: int):
        """Validate the limit value.

        Parameters
        ----------
        limit: int
            The limit value.

        Raises
        ----------
        WazuhError
            Raises if the limit value is less than 1.
        """
        if limit < 1:
            raise WazuhError(1401)

    def apply(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply the offset and limit filters to the data.

        Parameters
        ----------
        data:  List[Dict[str, Any]]
            The data to be filtered.

        Returns
        ----------
        List[Dict[str, Any]
            The filtered data.

        Note:
            The filter is applied to a list of dictionaries.
        """
        return data[self.offset:self.offset+self.limit]


def sort_by_filters(filters: List[Dict[str, Any]], data: Dict[str, Any]) -> tuple:
    """
    Sorts data based on the provided filters and returns a tuple of sorted values.

    Parameters
    ----------
    filters: List[Dict[str, Any]]
        A list of filter dictionaries specifying the fields and sorting options.
        Each filter dictionary should have the following keys:
            - 'fields': List[str]
                A list of strings representing the fields to filter and sort by.
            - 'reverse': bool
                A boolean value indicating whether to sort in reverse order.
    data: Dict[str, Any]
        A dictionary containing the data to be filtered and sorted.


    Returns
    ----------
    tuple:
        A tuple containing the sorted values based on the filters.
    """

    final_tuple = []

    for filter_dict in filters:
        value_of_filter = data
        for key in filter_dict['fields']:
            value_of_filter = value_of_filter.get(key)

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


class FieldSort(BaseQuery):
    """Filter to sort a list of dictionaries based on a field or fields."""

    def __init__(self, params: Dict[str, Any]):
        self.sort = params['sort']

    @staticmethod
    def should_apply(filters: Dict[str, Any], data: Any) -> bool:
        """ Check if the filter can be applied to the given filters and data.

        Parameters
        ----------
        filters: Dict[str, Any]
            The filters used for the filter.
        data: Any
            The data to be filtered.

        Returns
        ----------
        bool
            True if the filter can be applied, False otherwise.
        """
        if 'sort' in filters and filters['sort'] and isinstance(data, list):
            return True
        return False

    def apply(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply the sort filter to the data.

        Parameters
        ----------
        data:  List[Dict[str, Any]]
            The data to be filtered.

        Returns
        ----------
        List[Dict[str, Any]
            The filtered data.

        Note:
            The filter is applied to a list of dictionaries.
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

        # Sort the data using the sorting criteria and the sort_by_filters function as the key
        result = sorted(data, key=lambda x: sort_by_filters(list_of_sort, x))
        return result


class FieldQuery(BaseQuery):
    """Class for applying field-based queries to data."""

    def __init__(self, params: Dict[str, Any]):
        self.q = params['q']


    @staticmethod
    def should_apply(filters: Dict[str, Any], data: Any) -> bool:
        """
        Check if the field-based query filter can be applied.

        Parameters
        ----------
        filters: Dict[str, Any]
            The filters used for the filter.
        data: Any
            The data to be filtered.

        Returns
        ----------
        bool
            True if the filter can be applied, False otherwise.
        """
        if 'q' in filters and filters['q'] and isinstance(data, list):
            return True
        return False

    def apply(self, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Apply the field-based query filter to the given data.

        Parameters
        ----------
        data:  List[Dict[str, Any]]
            The data to be filtered.

        Returns
        ----------
        List[Dict[str, Any]
            The filtered data.
        """
        return filter_array_by_query(self.q, data)


class EngineQuery:
    """Sequence of response queries."""

    def __init__(self, queries: List[Type[BaseQuery]]):
        self.queries = queries

    def apply_sequence(self, params: Dict[str, Any], data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply the sequence of queries to the data.

        Parameters
        ----------
        params: Dict[str, Any]
            The filters used for the queries.
        data: List[Dict[str, Any]]
            The data to be filtered.


        Returns
        ----------
        List[Dict[str, Any]
            The filtered data.

        Note:
            The queries are applied in the order specified in the sequence.
        """
        filtered_data = data
        for query in self.queries:
            if query.should_apply(filters=params, data=data):
                filtered_data = query(params=params).apply(filtered_data)

        return filtered_data

    @classmethod
    def default_sequence(cls):
        """Create a default sequence of queries.

        Returns
        ----------
        EngineQuery
            An instance of EngineQuery with the default filters.
        """
        list_of_filters = [
            FieldSearch, FieldQuery, FieldSelector,
            FieldOffsetLimit, FieldSort]

        return cls(list_of_filters)
