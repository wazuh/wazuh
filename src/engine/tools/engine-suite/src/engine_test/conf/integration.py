from enum import Enum
from engine_test.conf.event_tester_template import TesterMessageTemplate


class CollectModes(Enum):
    '''
    Represents the possible collection of modes for engine-test recollection events.
    '''
    SINGLE_LINE = "single-line"
    MULTI_LINE = "multi-line"
    DYNAMIC_MULTI_LINE = "dynamic-multi-line"
    WINDOWS_EVENTCHANNEL = "windows-eventchannel"

    def get_collect_modes():
        collect_modes = []
        for collect_mode in CollectModes:
            collect_modes.append(collect_mode.value)
        return collect_modes

    def str_to_enum(collect_mode) -> 'CollectModes':
        if collect_mode == CollectModes.SINGLE_LINE.value:
            return CollectModes.SINGLE_LINE
        if collect_mode == CollectModes.MULTI_LINE.value:
            return CollectModes.MULTI_LINE
        if collect_mode == CollectModes.DYNAMIC_MULTI_LINE.value:
            return CollectModes.DYNAMIC_MULTI_LINE
        if collect_mode == CollectModes.WINDOWS_EVENTCHANNEL.value:
            return CollectModes.WINDOWS_EVENTCHANNEL
        raise ValueError(f"Invalid collect_mode: {collect_mode}")

    def enum_to_str(collect_mode) -> str:
        return collect_mode.value

    def is_collected_as_multiline(collect_mode: 'CollectModes') -> bool:
        if collect_mode == CollectModes.SINGLE_LINE:
            return False
        if collect_mode == CollectModes.MULTI_LINE:
            return True
        if collect_mode == CollectModes.DYNAMIC_MULTI_LINE:
            return True
        if collect_mode == CollectModes.WINDOWS_EVENTCHANNEL:
            return True
        raise ValueError("Invalid collect_mode.")


class IntegrationConf:
    '''
    Represents the configuration of an integration.
    '''

    def __init__(self, name: str, collect_mode: str, queue: str, location: str, lines: int = None):
        '''
        Represents the configuration of an integration.
        '''
        self.name: str = name

        self.collect_mode = CollectModes.str_to_enum(collect_mode)
        self.lines: int = lines  # Only for multi-line collect mode

        if self.collect_mode == None:
            raise ValueError("Invalid collect mode.")

        if self.collect_mode == CollectModes.MULTI_LINE and lines == None:
            raise ValueError("Lines are required for multi-line collect mode.")

        # Only create template if both queue and location are provided
        if queue and location:
            self.template = TesterMessageTemplate(queue, location)
        else:
            self.template = None

    def dump_as_tuple(self) -> tuple:
        '''
        Dumps the configuration as pair integration name and data.
        '''
        data = {
            "collect_mode": self.collect_mode.value,
        }
        if self.template:
            data["template"] = self.template.dump_template()
        if self.lines != None:
            data["lines"] = self.lines

        return (self.name, data)

    @staticmethod
    def from_tuple(name: str, data: dict) -> 'IntegrationConf':
        '''
        Creates an IntegrationConf from a pair of integration name and data.
        '''
        collect_mode = CollectModes.str_to_enum(data["collect_mode"])
        lines = data.get("lines", None)
        template_data = data.get("template")
        queue = ""
        location = ""

        # Extract necessary values from the template data for initialization
        if template_data:
            queue = template_data["event"]["queue"]
            location = template_data["event"]["location"]

        # Create a new instance with the extracted values
        instance = IntegrationConf(name, collect_mode.value, queue, location, lines)

        # Restore the full template data
        if template_data and instance.template:
            instance.template.reload_template(template_data)

        return instance

    def get_template(self) -> TesterMessageTemplate:
        '''
        Returns the template of the integration.
        '''
        if not self.template:
            raise RuntimeError("No template defined for this integration.")
        return self.template
