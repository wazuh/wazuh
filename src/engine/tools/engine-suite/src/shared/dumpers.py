import yaml

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

def dict_to_yml(data) -> str:
    data = yaml.dump(data, sort_keys=True, Dumper=EngineDumper, allow_unicode=True)
    return data
