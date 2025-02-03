import json
import requests
from importlib.metadata import files
from enum import Enum, auto
from pathlib import Path, PurePath
from typing import Tuple, List
import socket
import shared.executor as exec

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
        self._files = files('engine-suite')

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
            print(f"Error while reading YAML file:{e}")
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
            content_str = json.dumps(content)
            path = path.with_suffix('.json')
        elif Format.YML == format:
            content_str = yaml.dump(content, Dumper=Dumper, sort_keys=False)
            path = path.with_suffix('.yml')
        else:
            raise Exception(f'Trying to store file with format not supported')

        Path(path).write_text(content_str)

    def load_internal_file(self, name: str, module: str = '', format: Format = Format.JSON) -> dict:
        full_name = '/'.join([module, name]) if len(module) > 0 else name
        file = [p for p in self._files if full_name in str(p)][0]
        content = file.read_text()

        readed = self._read(content, format)
        if not readed:
            raise Exception(f'Failed to read {full_name}')

        return readed

    def delete_file(self, path: str):
        Path(path).unlink()

    def download_file(self, url: str, format: Format = Format.YML) -> dict:
        file = requests.get(url)
        if not file.ok:
            raise Exception(f"Error downloading {url}: {rFlat.status_code}")

        readed = self._read(file.text, format)
        if not readed:
            raise Exception(f'Failed to read {file.name}')
        return readed

    def _load_file(self, path: Path, format: Format = Format.YML) -> dict:
        content = path.read_text()

        if format == Format.TEXT:
            return content

        read = {}
        try:
            read = self._read(content, format)
        except:
            raise Exception(f'Failed to read {path.name}')
        return read

    def load_file(self, path_str: str, format: Format = Format.YML):
        path = Path(path_str)
        return self._load_file(path, format)

    def load_original_asset(self, path_str: str, format: Format = Format.YML) -> Tuple[str, str]:
        as_dict = self.load_file(path_str, format)
        name = as_dict['name']
        original = self.load_file(path_str, Format.TEXT)

        return name, original

    def load_module_files(self, module_path_str: str) -> Tuple[dict, dict]:
        module_path = Path(module_path_str)
        fields_definition = self._load_file(
            module_path/'fields.yml', Format.YML)
        logpar_overrides = None
        logpar_path = module_path/'logpar.json'
        if logpar_path.exists():
            logpar_overrides = self._load_file(logpar_path, Format.JSON)

        return fields_definition, logpar_overrides, module_path.name

    def save_file(self, path_str: str, name: str, content: dict, format: Format):
        path = Path(path_str)
        path.mkdir(parents=True, exist_ok=True)
        pure_path = PurePath(path / name)

        self._write_file(pure_path, content, format)

    def save_plain_text_file(self, path_str: str, name: str, content: str):
        path = Path(path_str)
        path.mkdir(parents=True, exist_ok=True)
        pure_path = PurePath(path / name)
        Path(pure_path).write_text(content)

    def read_plain_text_file(self, path_str: str) -> str:
        path = Path(path_str)
        with path.open(mode='r') as fid:
            content = fid.read()
        if not content:
            raise Exception(f'Failed to read plain text {path_str}')
        return content

    def create_dir(self, path_str: str):
        path = Path(path_str)
        path.mkdir(parents=True, exist_ok=False)

    def create_file(self, path_str: str, content: str = ""):
        path = Path(path_str)
        path.write_text(content)

    def walk_dir(self, path_str: str, function, recursive: bool = False):
        path = Path(path_str)
        if path.exists():
            if recursive:
                for entry in path.rglob('*'):
                    if entry.is_file():
                        function(entry)
            else:
                for entry in path.iterdir():
                    if entry.is_file():
                        function(entry)

    def current_dir_name(self) -> str:
        return str(Path.cwd().name)

    def cwd(self) -> str:
        return str(Path.cwd())
