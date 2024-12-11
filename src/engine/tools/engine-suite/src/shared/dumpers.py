import yaml
import json

try:
    from yaml import CDumper as BaseDumper
except ImportError:
    from yaml import Dumper as BaseDumper

class EngineDumper(BaseDumper):
    def represent_scalar(self, tag, value, style=None):
        # If the value contains a single quote, force double quotes
        if style is None and "'" in value:
            style = '"'
        # If the value contains a line break, force literal style
        if '\n' in value:
            style = '|'
        return super(EngineDumper, self).represent_scalar(tag, value, style)

def dict_to_str_yml(data) -> str:
    data = yaml.dump(data, sort_keys=True, Dumper=EngineDumper, allow_unicode=True)
    return data

def dict_to_str_json(data, pretty=False) -> str:
    if pretty:
        data = json.dumps(data, indent=2, sort_keys=True, separators=(',', ': '))
    else:
        data = json.dumps(data, separators=(',', ':'))
    return data
