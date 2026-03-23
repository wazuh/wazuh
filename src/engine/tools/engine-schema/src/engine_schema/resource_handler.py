import json
from enum import Enum, auto
from pathlib import Path, PurePath
from typing import Tuple

import yaml
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


class Format(Enum):
    JSON = auto()
    YML = auto()
    TEXT = auto()


def StringToFormat(string: str) -> Format:

    if string == 'json':
        return Format.JSON
    if string == 'yml' or string == 'yaml':
        return Format.YML
    if string == 'text':
        return Format.TEXT

    raise Exception(f'Format {string} not supported')


class ResourceHandler:
    def __init__(self):
        # Get the path to the engine_schema module directory directly
        self._module_path = Path(__file__).parent

    ############################################################################
    #                          File operations
    ############################################################################

    def _read_json(self, content: str) -> dict:
        read = {}
        try:
            read = json.loads(content)
        except ValueError as e:  # includes simplejson.decoder.JSONDecodeError
            print(f'Error while reading JSON file: {e}')
        return read

    def _read_yml(self, content: str) -> dict:
        read = {}
        try:
            read = yaml.load(content, Loader=Loader)  # yaml.SafeLoader
        except yaml.YAMLError as e:
            raise e
        return read

    def _read(self, content: str, format: Format) -> dict:
        if Format.JSON == format:
            return self._read_json(content)
        elif Format.YML == format:
            return self._read_yml(content)
        else:
            raise Exception(f'Trying to read file with format not supported')

    def _write_file(self, path: PurePath, content: dict, format: Format):
        content_str = ''
        if Format.JSON == format:
            content_str = json.dumps(content, indent=2, sort_keys=True, ensure_ascii=False)
            path = path.with_suffix('.json')
        elif Format.YML == format:
            content_str = yaml.dump(content, Dumper=Dumper, sort_keys=False)
            path = path.with_suffix('.yml')
        else:
            raise Exception(f'Trying to store file with format not supported')

        Path(path).write_text(content_str, encoding='utf-8')

    def load_internal_file(self, name: str, module: str = '', format: Format = Format.JSON) -> dict:
        # Template files mapping
        template_files = {
            'fields.template': 'fields.template.json',
            'logpar_types': 'logpar_types.json'
        }

        filename = template_files.get(name, f'{name}.json')
        file_path = self._module_path / filename

        if not file_path.exists():
            raise FileNotFoundError(f'Template file not found: {file_path}')

        content = file_path.read_text()
        readed = self._read(content, format)
        if not readed:
            raise Exception(f'Failed to read {name}')

        return readed

    def _load_file(self, path: Path, format: Format = Format.YML) -> dict:
        content = path.read_text()

        if format == Format.TEXT:
            return content

        read = {}
        try:
            read = self._read(content, format)
        except Exception as e:
            print(f'Failed to read {path.name}')
            raise e
        return read

    def load_file(self, path_str: str, format: Format = Format.YML):
        path = Path(path_str)
        return self._load_file(path, format)

    def save_file(self, path_str: str, name: str, content: dict, format: Format):
        path = Path(path_str)
        path.mkdir(parents=True, exist_ok=True)
        pure_path = PurePath(path / name)

        self._write_file(pure_path, content, format)
