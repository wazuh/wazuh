import json
import requests
from importlib.metadata import files
from enum import Enum, auto
from pathlib import Path, PurePath
from typing import Tuple
import socket

import yaml
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


class Format(Enum):
    JSON = auto()
    YML = auto()
    TEXT = auto()


class ResourceHandler:
    def __init__(self):
        self._files = files('engine-suite')

    def _read_json(self, content: str) -> dict:
        try:
            read = json.loads(content)
        except ValueError:  # includes simplejson.decoder.JSONDecodeError
            print('Error while reading JSON file')
        return read

    def _read_yml(self, content: str) -> dict:
        try:
            read = yaml.load(content, Loader=Loader)  # yaml.SafeLoader
        except yaml.YAMLError:
            print("Error while reading YAML file")
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
        read = {}
        try:
            read = self._read(content, format)
        except:
            raise Exception(f'Failed to read {path.name}')
        return read

    def load_file(self, path_str: str, format: Format = Format.YML) -> dict:
        path = Path(path_str)
        return self._load_file(path, format)

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

    def _base_catalog_command(self, path: str, type: str, name: str, content: dict, format: Format, command: str):
        raw_message = ''
        format_str = ''
        if format is Format.JSON:
            raw_message = json.dumps(content)
            format_str = 'json'
        elif format is Format.YML:
            raw_message = yaml.dump(content, Dumper=Dumper, sort_keys=False)
            format_str = 'yaml'
        elif command != 'delete':
            raise Exception(f'Format not supported for catalog {name}')

        request = {'version': 1, 'command': 'catalog.resource/' + command, 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': {'type': type, 'name': name, 'content': raw_message, 'format': format_str}}
        request_raw = json.dumps(request)
        request_bytes = len(request_raw).to_bytes(4, 'little')
        request_bytes += request_raw.encode('utf-8')

        data = b''
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(path)
            s.sendall(request_bytes)
            data = s.recv(65507)

        resp_size = int.from_bytes(data[:4], 'little')
        resp_message = data[4:resp_size+4].decode('UTF-8')

        # Change post for update and put for add
        if command == 'post':
            command = 'add'
        elif command == 'put':
            command = 'update'

        if not len(resp_message):
            raise Exception(
                f'Catalog command [{command}] received an empty response.')

        try:
            response = json.loads(resp_message)
            if response['data']['status'] != 'OK':
                raise Exception(
                    f'Could not execute [{command}] [{name}] due to: {response["data"]["error"]}')
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')

    def update_catalog_file(self, path: str, name: str, content: dict, format: Format):
        self._base_catalog_command(path, type, name, content, format, 'put')

    def add_catalog_file(self, path: str, type: str, name: str, content: dict, format: Format):
        self._base_catalog_command(path, type, name, content, format, 'post')

    def delete_catalog_file(self, path: str, type: str, name: str):
        self._base_catalog_command(path, type, name, [], format, 'delete')

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
            raise Exception(f'Failed to read plain text {full_name}')
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

    def _base_command_kvdb(self, api_socket: str, name: str, path: str, subcommand):
        request = {'version': 1, 'command': 'kvdb.manager/' + subcommand, 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': {'name': name, 'path': path}}
        request_raw = json.dumps(request)
        request_bytes = len(request_raw).to_bytes(4, 'little')
        request_bytes += request_raw.encode('utf-8')

        data = b''
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(api_socket)
            s.sendall(request_bytes)
            data = s.recv(65507)

        resp_size = int.from_bytes(data[:4], 'little')
        resp_message = data[4:resp_size+4].decode('UTF-8')

        if not len(resp_message):
            raise Exception(
                f'KVDB command [{subcommand}] received an empty response.')

        try:
            resp_message = json.loads(resp_message)
            if resp_message['data']['status'] != 'OK':
                raise Exception(
                    f'Could not execute [{subcommand}] in [{name}] due to: {resp_message["data"]["error"]}')
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')

    def create_kvdb(self, api_socket: str, name: str, path: str):
        self._base_command_kvdb(api_socket, name, path, 'post')

    def delete_kvdb(self, api_socket: str, name: str, path: str):
        self._base_command_kvdb(api_socket, name, path, 'delete')

    def _base_recursive_command_on_kvdbs(self, api_socket: str, path_str: str, command: str, print_name: bool = False):
        path = Path(path_str) / 'kvdbs'
        if path.exists():
            for entry in path.rglob('*'):
                if entry.is_file():
                    # Change post for create
                    command_str = command
                    if command == 'post':
                        command_str = 'create'
                    if print_name:
                        print(
                            f'Applying [{command_str}] command to "{entry.stem}"')
                    self._base_command_kvdb(
                        api_socket, entry.stem, str(entry), command)
                else:
                    raise Exception(f'"kvdbs" Directory should contain files')
        else:
            raise Exception(
                f'Could not execute [{command}] command in "{name}" due to: unexistent path "{path_str}"')

    def recursive_create_kvdbs(self, api_socket: str, path_str: str, print_name: bool = False):
        self._base_recursive_command_on_kvdbs(
            api_socket, path_str, 'post', print_name)

    def recursive_delete_kvdbs(self, api_socket: str, path_str: str, print_name: bool = False):
        self._base_recursive_command_on_kvdbs(
            api_socket, path_str, 'delete', print_name)

    def _recursive_command_to_catalog(self, api_socket: str, path_str: str, type: str, command: str, print_name: bool = False):
        path = Path(path_str) / type
        if path.exists():
            for entry in path.rglob('*'):
                if entry.is_file():
                    component = []
                    name = entry.stem
                    component = self.load_file(entry, Format.YML)
                    name = component['name']
                    if print_name:
                        print(
                            f'Applying {command} command to {name} {type[:-1]}')
                    self._base_catalog_command(
                        api_socket, type[:-1], name, component, Format.YML, command)
                else:
                    raise Exception(f'{entry} is not a file.')
        else:
            raise Exception(f'{path_str}/{type} does not exist.')

    def recursive_load_catalog(self, api_socket: str, path_str: str, type: str, print_name: bool = False):
        self._recursive_command_to_catalog(
            api_socket, path_str, type, 'post', print_name)

    def recursive_update_catalog(self, api_socket: str, path_str: str, type: str, print_name: bool = False):
        self._recursive_command_to_catalog(
            api_socket, path_str, type, 'put', print_name)

    def recursive_delete_catalog(self, api_socket: str, path_str: str, type: str, print_name: bool = False):
        self._recursive_command_to_catalog(
            api_socket, path_str, type, 'delete', print_name)
