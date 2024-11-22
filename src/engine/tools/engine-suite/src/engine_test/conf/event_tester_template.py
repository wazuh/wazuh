from enum import Enum
import json
import datetime
import copy


class SubTempleType(Enum):
    '''
    Represents the type of template to be updated.
    '''
    HEADER = '_header_template'
    EVENT = '_event_template'


class TesterMessageTemplate:
    '''
    Represents a template for a tester message, including the header and all type of events.
    '''
    TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ" # 2023-12-26T09:22:14.000Z

    def __init__(self, provider: str, module: str, ingested: str = "auto"):
        '''
        Initializes the template with the given provider, module and ingested time.

        Args:
            provider (str): The provider of the event.
            module (str): The module of the event.
            ingested (str): The ingested time of the event. If "auto", the current time will be used.

        Raises:
            ValueError: If the ingested time is not in the correct format.
        '''

        # Check if the ingested time is auto
        if ingested.lower() != "auto":
            # If not, convert it to the time format
            try:
                datetime.datetime.strptime(ingested, self.TIME_FORMAT)
            except ValueError:
                raise ValueError(
                    f"Invalid ingested time format. Expected format: {self.TIME_FORMAT}")

        self._header_template = {
            "agent": {
                "id": "2887e1cf-9bf2-431a-b066-a46860080f56",
                "name": "wazuh-agent-name",
                "type": "endpoint",
                "version": "5.0.0",
                "groups": ["group1", "group2"],
                "host": {
                    "hostname": "wazuh-endpoint-linux",
                    "os": {"name": "Amazon Linux 2", "platform": "Linux"},
                    "ip": ["192.168.1.2"],
                    "architecture": "x86_64"
                }
            }
        }

        self._event_template = {
            "base": {"tags": ["production-server"]},
            "event": {
                "ingested": ingested,
                "module": module,
                "original": "$EVENT_AS_STRING",
                "provider": provider
            },
            "log": {"file": {"path": "$OPTIONAL_IF_PROVIDER_IS_FILE"}}
        }

    @staticmethod
    def from_template(template_dict):
        '''
        Creates a TesterMessageTemplate from a dictionary.
        '''
        instance = TesterMessageTemplate("", "")
        instance._load_template(template_dict)
        return instance

    def dump_template(self) -> dict:
        '''
        Dumps the template as a dictionary.
        '''
        return {"header": self._header_template, "event": self._event_template}

    def _load_template(self, template_dict: dict):
        '''
        Loads the template from a dictionary.
        '''

        self._header_template = template_dict['header']
        self._event_template = template_dict['event']

    def get_header(self):
        return json.dumps(self._header_template, separators=(',', ':'))

    def get_event(self, event: str):
        _event_template = copy.deepcopy(self._event_template)
        _event_template['event']['original'] = event
        if _event_template['event']['ingested'].lower() == "auto":
            _event_template['event']['ingested'] = datetime.datetime.now(
                datetime.timezone.utc).strftime(self.TIME_FORMAT)
        return json.dumps(_event_template, separators=(',', ':'))

    def update_field(self, sub_template: SubTempleType, field_path, value):
        json_object = getattr(self, sub_template.value)
        keys = field_path.split('.')
        for key in keys[:-1]:
            json_object = json_object.setdefault(key, {})
        json_object[keys[-1]] = value

    def add_field(self, sub_template: SubTempleType, field_path, value):
        self.update_field(sub_template, field_path, value)

    def remove_field(self, sub_template: SubTempleType, field_path):
        json_object = getattr(self, sub_template.value)

        keys = field_path.split('.')
        current = json_object
        path_to_current = []

        # Traverse to the item just before the last key
        for key in keys[:-1]:
            if key in current:
                path_to_current.append(current)
                current = current[key]
            else:
                raise KeyError(f"Field '{key}' does not exist in the path '{field_path}'.")

        # Remove the final key
        if keys[-1] in current:
            del current[keys[-1]]
        else:
            raise KeyError(f"Field '{keys[-1]}' does not exist to remove.")

        # Clean up empty dictionaries going backward from the point of deletion
        for parent in reversed(path_to_current):
            if not current:
                key_to_remove = list(parent.keys())[list(parent.values()).index(current)]
                del parent[key_to_remove]
            current = parent



    def _get_nested_dict(self, base_dict, keys, should_create=True):
        for key in keys:
            if should_create:
                # Use setdefault to handle non-existent keys gracefully
                base_dict = base_dict.setdefault(key, {})
            else:
                if key in base_dict:
                    base_dict = base_dict[key]
                else:
                    raise KeyError(
                        f"Field '{key}' does not exist in the path.")
        return base_dict
