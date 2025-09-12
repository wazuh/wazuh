import json
import copy


class TesterMessageTemplate:
    '''
    Represents a template for a tester message, including the header and all type of events.
    '''

    def __init__(self, queue: str, location: str):
        '''
        Initializes the template with the given provider, module and created time.

        Args:
            queue (str): The queue of the event.
            location (str): The location of the event.

        Raises:
            ValueError: If the created time is not in the correct format.
        '''

        self.template = {
            "event": {
                "queue": queue,
                "location": location,
                "message": ""
            }
        }

    def reload_template(self, template_dict):
        '''
        Reloads the template from a dictionary.
        '''
        self._load_template(template_dict)


    def dump_template(self) -> dict:
        """
        Returns a deep copy of the template as a dictionary.
        """
        return copy.deepcopy(self.template)


    def _load_template(self, template_dict: dict):
        '''
        Loads the template from a dictionary.
        '''
        self.template = template_dict

    def get_event(self, event: str):
        '''
        Returns the event as a JSON string of one line, according to the template.
        '''
        _event_template = copy.deepcopy(self.template)
        _event_template['event']['message'] = event
        return _event_template['event']['message']

    def _update_field(self, field_path, value):
        '''
        Updates a field in the template, given the path and the value.
        If the field does not exist, it will be created.
        '''
        keys = field_path.split('.')
        obj = self.template
        for key in keys[:-1]:
            obj = obj.setdefault(key, {})
        obj[keys[-1]] = value

    def add_field(self, field_path, value):
        '''
        Adds a field to the template, given the path and the value.
        '''
        self._update_field(field_path, value)

    def remove_field(self, field_path):
        '''
        Removes a field from the template, given the path.
        '''
        keys = field_path.split('.')
        obj = self.template
        parents = []  # stack of (parent_obj, key)
        for key in keys[:-1]:
            if key in obj:
                parents.append((obj, key))
                obj = obj[key]
            else:
                raise KeyError(f"Path '{field_path}' not found.")
        # Delete the final key
        if keys[-1] in obj:
            del obj[keys[-1]]
        else:
            raise KeyError(f"Field '{keys[-1]}' not found in path '{field_path}'.")
        # Cleanup empty dictionaries
        for parent, key in reversed(parents):
            child = parent[key]
            if not child:
                del parent[key]
