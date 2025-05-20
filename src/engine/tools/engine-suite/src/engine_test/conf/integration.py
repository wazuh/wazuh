from enum import Enum
from engine_test.conf.event_tester_template import TesterMessageTemplate, SubTempleType


class Formats(Enum):
    '''
    Represents the possible formats or modes for engine-test recollection events.
    '''
    SINGLE_LINE = "single-line"
    MULTI_LINE = "multi-line"
    DYNAMIC_MULTI_LINE = "dynamic-multi-line"
    WINDOWS_EVENTCHANNEL = "windows-eventchannel"

    def get_formats():
        formats = []
        for format in Formats:
            formats.append(format.value)
        return formats

    def str_to_enum(format) -> 'Formats':
        if format == Formats.SINGLE_LINE.value:
            return Formats.SINGLE_LINE
        if format == Formats.MULTI_LINE.value:
            return Formats.MULTI_LINE
        if format == Formats.DYNAMIC_MULTI_LINE.value:
            return Formats.DYNAMIC_MULTI_LINE
        if format == Formats.WINDOWS_EVENTCHANNEL.value:
            return Formats.WINDOWS_EVENTCHANNEL
        raise ValueError(f"Invalid format: {format}")

    def enum_to_str(format) -> str:
        return format.value

    def is_collected_as_multiline(format: 'Formats') -> bool:
        if format == Formats.SINGLE_LINE:
            return False
        if format == Formats.MULTI_LINE:
            return True
        if format == Formats.DYNAMIC_MULTI_LINE:
            return True
        if format == Formats.WINDOWS_EVENTCHANNEL:
            return True
        raise ValueError("Invalid format.")


class IntegrationConf:
    '''
    Represents the configuration of an integration.
    '''

    def __init__(self, name: str, format: str, module: str, collector: str, provider: str, date: str, lines: int = None):
        '''
        Represents the configuration of an integration.
        '''
        self.name: str = name

        self.format = Formats.str_to_enum(format)
        self.lines: int = lines  # Only for multi-line format

        if self.format == None:
            raise ValueError("Invalid format.")

        if self.format == Formats.MULTI_LINE and lines == None:
            raise ValueError("Lines are required for multi-line format.")

        # Create template
        self.template = TesterMessageTemplate(
            provider, module, collector, date)

    def dump_as_tuple(self) -> tuple:
        '''
        Dumps the configuration as pair integration name and data.
        '''
        data = {
            "format": self.format.value,
            "template": self.template.dump_template()
        }
        if self.lines != None:
            data["lines"] = self.lines

        return (self.name, data)

    @staticmethod
    def from_tuple(name: str, data: dict) -> 'IntegrationConf':
        '''
        Creates an IntegrationConf from a pair of integration name and data.
        '''
        format = Formats.str_to_enum(data["format"])
        lines = data.get("lines", None)
        template_data = data["template"]

        # Extract necessary values from the template data for initialization
        collector = template_data["subheader"]["collector"]
        module = template_data["subheader"]["module"]
        provider = template_data["event"]["event"]["provider"] if "provider" in template_data["event"]["event"] else None
        date = template_data["event"]["event"]["created"]

        # Create a new instance with the extracted values
        instance = IntegrationConf(
            name, format.value, module, collector, provider, date, lines)

        # Restore the full template data
        instance.template.reload_template(template_data)

        return instance

    def get_template(self) -> TesterMessageTemplate:
        '''
        Returns the template of the integration.
        '''
        return self.template
