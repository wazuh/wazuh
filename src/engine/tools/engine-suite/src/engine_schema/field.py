from __future__ import annotations
from enum import Enum, auto


# Pattern to allow mapping strings of helpers and refs
REF_STR_PATTERN = '^\\$[\\w\\.]+$'
HELPER_STR_PATTERN = '^[\\w]+\\(.*\\)$'
HELPER_REF_STR_PATTERN = f'{REF_STR_PATTERN}|{HELPER_STR_PATTERN}'


class IndexerType(Enum):
    KEYWORD = auto()
    IP = auto()
    LONG = auto()
    OBJECT = auto()
    GEO_POINT = auto()
    NESTED = auto()
    SCALED_FLOAT = auto()
    TEXT = auto()
    BOOLEAN = auto()
    DATE = auto()
    FLOAT = auto()
    ARRAY = auto()
    WILDCARD = auto()

    def __str__(self):
        return f'{self.name}'.lower()

    @classmethod
    def from_str(cls, name: str):
        if name == str(cls.KEYWORD):
            return cls.KEYWORD
        elif name == str(cls.IP):
            return cls.IP
        elif name == str(cls.LONG):
            return cls.LONG
        elif name == str(cls.OBJECT):
            return cls.OBJECT
        elif name == str(cls.GEO_POINT):
            return cls.GEO_POINT
        elif name == str(cls.NESTED):
            return cls.NESTED
        elif name == str(cls.SCALED_FLOAT):
            return cls.SCALED_FLOAT
        elif name == str(cls.TEXT):
            return cls.TEXT
        elif name == str(cls.BOOLEAN):
            return cls.BOOLEAN
        elif name == str(cls.DATE):
            return cls.DATE
        elif name == str(cls.FLOAT):
            return cls.FLOAT
        elif name == str(cls.ARRAY):
            return cls.ARRAY
        elif name == str(cls.WILDCARD):
            return cls.WILDCARD
        else:
            raise Exception(f'"{name}" is not a valid IndexerType')


class JsonType(Enum):
    STRING = auto()
    OBJECT = auto()
    NUMBER = auto()
    ARRAY = auto()
    BOOLEAN = auto()

    def __str__(self):
        return f'{self.name}'.lower()

    @classmethod
    def from_str(cls, name: str):
        if name == str(cls.STRING):
            return cls.STRING
        elif name == str(cls.OBJECT):
            return cls.OBJECT
        elif name == str(cls.NUMBER):
            return cls.NUMBER
        elif name == str(cls.ARRAY):
            return cls.ARRAY
        elif name == str(cls.BOOLEAN):
            return cls.BOOLEAN
        else:
            raise Exception(f'"{name}" is not a valid JsonType')


def indexer_to_json_type(indexer_type: IndexerType) -> JsonType:
    # Object types
    if indexer_type == IndexerType.OBJECT:
        return JsonType.OBJECT
    if indexer_type == IndexerType.NESTED:
        return JsonType.OBJECT

    # String types
    if indexer_type == IndexerType.DATE:
        return JsonType.STRING
    if indexer_type == IndexerType.IP:
        return JsonType.STRING
    if indexer_type == IndexerType.TEXT:
        return JsonType.STRING
    if indexer_type == IndexerType.GEO_POINT:
        return JsonType.STRING
    if indexer_type == IndexerType.KEYWORD:
        return JsonType.STRING
    if indexer_type == IndexerType.WILDCARD:
        return JsonType.STRING

    # Numeric types
    if indexer_type == IndexerType.LONG:
        return JsonType.NUMBER
    if indexer_type == IndexerType.SCALED_FLOAT:
        return JsonType.NUMBER
    if indexer_type == IndexerType.FLOAT:
        return JsonType.NUMBER

    # Boolean types
    if indexer_type == IndexerType.BOOLEAN:
        return JsonType.BOOLEAN

    raise Exception(
        f'Indexer type {indexer_type} does not have json representation')


class Field:
    """Class to represent the fields that are indexed

    The name includes the whole parent group fields concatenade with dots
    """

    def __init__(
            self, module: str, name: str, description: str, indexer_type: IndexerType, array: bool = False,
            indexer_details: dict = None):
        # Metadata
        self.module = module
        self.name = name
        self.description = description

        # Type info
        self.indexer_type = indexer_type
        self.array = array
        self.json_type = indexer_to_json_type(indexer_type)
        self.indexer_details = indexer_details

        # Assert additional info is passed if needed
        if self.indexer_type == IndexerType.SCALED_FLOAT:
            if not (self.indexer_details and 'scaling_factor' in self.indexer_details):
                raise Exception(
                    f'Indexer type {self.indexer_type} requires scaling_factor in indexer_details for field {self.name}')

        # if self.indexer_type == IndexerType.KEYWORD:
        #     if not (self.indexer_details and 'ignore_above' in self.indexer_details):
        #         raise Exception(
        #             f'Indexer type {self.indexer_type} requires ignore_above in indexer_details for field {self.name}')

        # Transform multi_fields to the mappings format
        if self.indexer_details and 'multi_fields' in self.indexer_details:
            self.indexer_details['fields'] = dict()
            for multi_field in self.indexer_details['multi_fields']:
                self.indexer_details['fields'][multi_field['name']] = {
                    'type': multi_field['type']
                }
            self.indexer_details.pop('multi_fields')

    def to_jschema(self) -> dict:
        """Obtains the json that describes this field in the schema

        Returns:
            dict: schema json value for this field
        """

        obj = dict()
        obj['description'] = f'Module: {self.module}\nIndexerType: {self.indexer_type}\nArray: {self.array}\n\n{self.description}'

        # Prepare the type schema description
        _type = dict()
        _type['type'] = [str(self.json_type)]
        if self.json_type is not JsonType.STRING:
            _type['type'].append(str(JsonType.STRING))
            _type['pattern'] = HELPER_REF_STR_PATTERN

        # Add the type info
        if not self.array:
            # If it is not array, add it to the current property
            obj = {**obj, **_type}
        else:
            # Add array and pattern to current property, and add the _type to the items
            obj['type'] = [str(JsonType.STRING), str(JsonType.ARRAY)]
            obj['pattern'] = HELPER_REF_STR_PATTERN
            obj['items'] = _type

        return obj

    def to_jmapping(self) -> dict:
        """Obtains the json that describes the mapping in the indexer for this field

        Returns:
            dict: mapping json value for this field
        """

        obj = dict()

        # Add type description
        obj['type'] = str(self.indexer_type)

        # Add properties of the type
        if self.indexer_details:
            obj = {**obj, **self.indexer_details}

        return obj


class FieldTree:
    def __init__(self):
        self._tree = {'_root': dict()}
        self._root = self._tree['_root']
        self._children_tag = '_children'
        self._field_tag = '_field'
        self._logpar_overrides = dict()

    def _get_parts(self, path: str) -> list:
        return path.split('.')

    def _add_child_node(self, node: dict, part: str) -> dict:
        if self._children_tag not in node:
            node[self._children_tag] = dict()

        if part not in node[self._children_tag]:
            node[self._children_tag][part] = dict()

        return node[self._children_tag][part]

    def _add_field_node(self, path: str):
        parts = self._get_parts(path)
        current = self._root
        for part in parts:
            current = self._add_child_node(current, part)

        return current

    def _has_field_node(self, path: str) -> bool:
        parts = self._get_parts(path)
        current = self._root
        for part in parts:
            if self._children_tag in current and part in current[self._children_tag]:
                current = current[self._children_tag][part]
            else:
                return False

        return True

    def add_field(self, path: str, field: Field):
        node = self._add_field_node(path)
        node[self._field_tag] = field

    def _get_jschema_rec(self, properties: dict, current: dict, full_name: str):
        # Get type info
        if self._field_tag in current:
            field = current[self._field_tag]

            # Add info
            field_jschema = field.to_jschema()
            properties[full_name] = field_jschema

            # If object or array of objects add children (nested form)
            # a:
            #  b:
            #   c: ...
            if self._children_tag in current:
                next_properties = properties
                if str(JsonType.OBJECT) in field_jschema['type']:
                    properties[full_name]['additionalProperties'] = False
                    properties[full_name]['properties'] = dict()
                    next_properties = properties[full_name]['properties']
                elif str(JsonType.ARRAY) in field_jschema['type'] and str(JsonType.OBJECT) in field_jschema['items']['type']:
                    properties[full_name]['items']['additionalProperties'] = False
                    properties[full_name]['items']['properties'] = dict()
                    next_properties = properties[full_name]['items']['properties']
                else:
                    raise Exception(
                        f'{full_name} field node has children but is not object')

                for child_name, child_node in current[self._children_tag].items():
                    self._get_jschema_rec(
                        next_properties, child_node, child_name)

        # Default parent field object, add children in dotted form
        # a.b.c.d: ...
        elif self._children_tag in current:
            for child_name, child_node in current[self._children_tag].items():
                self._get_jschema_rec(
                    properties, child_node, full_name + '.' + child_name)

        else:
            raise Exception(
                f'{full_name} field node is default parent object with no children')

    def _default_jmap_type(self) -> dict:
        return {'type': str(IndexerType.OBJECT), 'properties': {}}

    def _get_jmapping_rec(self, properties: dict, current: dict, name: str):
        # Add type maping
        if self._field_tag in current:
            properties[name] = current[self._field_tag].to_jmapping()
        else:
            properties[name] = self._default_jmap_type()

        # Add children
        if self._children_tag in current:
            properties[name]['properties'] = dict()
            for child_name, child_node in current[self._children_tag].items():
                self._get_jmapping_rec(
                    properties[name]['properties'], child_node, child_name)

    def get_jschema(self) -> dict:
        jschema = dict()

        for name, node in self._root[self._children_tag].items():
            self._get_jschema_rec(jschema, node, name)

        return jschema

    def get_jmapping(self) -> dict:
        jmapping = dict()

        for name, node in self._root[self._children_tag].items():
            self._get_jmapping_rec(jmapping, node, name)

        return jmapping

    def add_logpar_overrides(self, logpar_overrides: dict):
        for k, v in logpar_overrides.items():
            if not self._has_field_node(k):
                raise Exception(
                    f'Logpar override for field {k} not found in the field tree')

        self._logpar_overrides = logpar_overrides

    def get_jlogpar(self) -> dict:
        return self._logpar_overrides

    def _merge_dicts(self, dict1, dict2):
        for key, value in dict2.items():
            if key in dict1:
                if isinstance(value, dict) and isinstance(dict1[key], dict):
                    dict1[key] = self._merge_dicts(dict1[key], value)
                else:
                    dict1[key] = value
            else:
                dict1[key] = value
        return dict1

    def merge(self, other: FieldTree):
        for k, v in other._root[self._children_tag].items():
            if self._has_field_node(k):
                if isinstance(self._root[self._children_tag].get(k), dict):
                    self._root[self._children_tag][k] = self._merge_dicts(
                        self._root[self._children_tag].get(k, {}),
                        v
                    )
            else:
                self._root[self._children_tag][k] = v

        for k, v in other._logpar_overrides.items():
            if k in self._logpar_overrides:
                raise Exception(
                    f'Error merging logpar override, field {k} already exists')

            self._logpar_overrides[k] = v
