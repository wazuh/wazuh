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

    def _base_catalog_command(self, path: str, type: str, name: str, content: str, namespace: str, format: Format, command: str):
        format_str = ''
        if format is Format.JSON:
            format_str = 'json'
        elif format is Format.YML:
            format_str = 'yaml'
        elif command != 'delete':
            raise Exception(f'Format not supported for catalog {name}')

        request = {'version': 1, 'command': 'catalog.resource/' + command, 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': {'type': type, 'name': name, 'content': content, 'namespaceid': namespace, 'format': format_str}}
        request_raw = json.dumps(request)
        request_bytes = len(request_raw).to_bytes(4, 'little')
        request_bytes += request_raw.encode('utf-8')

        data = b''
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            try:
                s.connect(path)
                s.sendall(request_bytes)
                data = s.recv(65507)
            except:
                raise Exception(
                    f'Could not connect and send information throug [{path}]')

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

        response = ''
        try:
            response = json.loads(resp_message)
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')
        if response['data']['status'] != 'OK':
            raise Exception(
                f'{response["data"]["error"]}')

    def update_catalog_file(self, path: str, type: str, name: str, content: dict, namespace: str, format: Format):
        self._base_catalog_command(
            path, type, name, content, namespace, format, 'put')

    def add_catalog_file(self, path: str, type: str, name: str, content: str, namespace: str, format: Format):
        self._base_catalog_command(
            path, type, name, content, namespace, format, 'post')

    def get_add_catalog_task(self, path: str, type: str, name: str, content: str, namespace: str, format: Format = Format.YML) -> exec.RecoverableTask:
        def do_task():
            self.add_catalog_file(path, type, name, content, namespace, format)
            return None

        def undo_task():
            self.delete_catalog_file(path, type, name, namespace)
            return None

        info = f'[{namespace}] Add {name} to catalog'

        return exec.RecoverableTask(do_task, undo_task, info)

    def get_update_catalog_task(self, path: str, type: str, name: str, content: str, namespace: str, format: Format = Format.YML) -> exec.RecoverableTask:
        backup = self.get_catalog_file(path, type, name, namespace)['data']['content']
        if backup == content:
            return None

        def do_task():
            self.update_catalog_file(
                path, type, name, content, namespace, format)
            return None

        def undo_task():
            self.update_catalog_file(
                path, type, name, backup, namespace, format)
            return None

        info = f'[{namespace}] Update {name} to catalog'

        return exec.RecoverableTask(do_task, undo_task, info)

    def delete_catalog_file(self, path: str, type: str, name: str, namespace: str, format: Format = Format.YML):
        self._base_catalog_command(
            path, type, name, [], namespace, format, 'delete')

    def get_delete_catalog_file_task(self, path: str, type: str, name: str, namespace: str) -> exec.RecoverableTask:
        backup = self.get_catalog_file(path, type, name, namespace, Format.JSON)[
            'data']['content']

        def do_task():
            self.delete_catalog_file(path, type, name)
            return None

        def undo_task():
            self.add_catalog_file(path, type, name, backup, Format.JSON)
            return None

        info = f'[{namespace}] Delete {name} from catalog'

        return exec.RecoverableTask(do_task, undo_task, info)

    def _base_catalog_get_command(self, path: str, type: str, name: str, namespace: str, format: Format) -> dict:
        format_str = ''
        # if command == 'get':
        #     format_str = 'yaml'
        if format is Format.JSON:
            format_str = 'json'
        elif format is Format.YML:
            format_str = 'yaml'
        else:
            raise Exception(f'Format not supported for catalog {name}')

        request = {'version': 1, 'command': 'catalog.resource/get', 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': {'type': type, 'name': name, 'content': '', 'namespaceid': namespace, 'format': format_str}}
        request_raw = json.dumps(request)
        request_bytes = len(request_raw).to_bytes(4, 'little')
        request_bytes += request_raw.encode('utf-8')

        data = b''
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            try:
                s.connect(path)
                s.sendall(request_bytes)
                data = s.recv(65507)
            except:
                raise Exception(
                    f'Could not connect and send information throug [{path}]')

        resp_size = int.from_bytes(data[:4], 'little')
        resp_message = data[4:resp_size+4].decode('UTF-8')

        if not len(resp_message):
            raise Exception(
                f'Catalog command [get] received an empty response.')

        response = ''
        try:
            response = json.loads(resp_message)
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')
        if response['data']['status'] != 'OK':
            raise Exception(
                f'{response["data"]["error"]}')

        if format is Format.JSON:
            return response
        else:
            return yaml.load(resp_message, Loader=Loader)

    def get_catalog_file(self, path: str, type: str, name: str, namespace: str, format: Format = Format.YML):
        return self._base_catalog_get_command(path, type, name, namespace, format)

    def list_catalog(self, path: str, name: str, namespace: str) -> list:
        response = self._base_catalog_get_command(
            path, '', name, namespace, Format.JSON)
        assets = json.loads(response['data']['content'])

        return assets

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

    def _get_all_namespaces(self, api_socket: str):
        request = {'version': 1, 'command': 'catalog.namespaces/get', 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': {}}
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
                f'Catalog command [namespaces] received an empty response.')

        try:
            resp_message = json.loads(resp_message)
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')

        if resp_message['data']['status'] != 'OK':
            raise Exception(
                f'{resp_message["data"]["error"]}')
        return resp_message

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
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')

        if resp_message['data']['status'] != 'OK':
            raise Exception(
                f'{resp_message["data"]["error"]}')
        elif subcommand == 'get':
            return resp_message

    def _base_send_command_kvdb(self, api_socket: str, subcommand, params: dict,  resource: str = "manager"):
        request = {'version': 1, 'command': f'kvdb.{resource}/' + subcommand, 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': params}
        request_raw = json.dumps(request)
        request_bytes = len(request_raw).to_bytes(4, 'little')
        request_bytes += request_raw.encode('utf-8')

        data = b''
        client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client_socket.connect(api_socket)
        client_socket.sendall(request_bytes)
        data = client_socket.recv(65507)

        resp_size = int.from_bytes(data[:4], 'little')
        resp_message = data[4:resp_size+4].decode('UTF-8')

        try:
            resp_message = json.loads(resp_message)
            client_socket.close()
            return resp_message
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')

    def create_kvdb(self, api_socket: str, name: str, path: str):
        self._base_command_kvdb(api_socket, name, path, 'post')

    def delete_kvdb(self, api_socket: str, name: str):
        self._base_command_kvdb(api_socket, name, '', 'delete')

    def get_create_kvdb_task(self, api_socket: str, name: str, path: str) -> exec.RecoverableTask:
        def do_task():
            self.create_kvdb(api_socket, name, path)
            return None

        def undo_task():
            self.delete_kvdb(api_socket, name)
            return None

        info = f'Add KVDB {name}'

        return exec.RecoverableTask(do_task, undo_task, info)

    def dump_kvdb(self, api_socket: str, name: str, path: str):
        self._base_command_kvdb(api_socket, name, path, 'dump')

    def get_kvdb_list(self, api_socket: str):
        return self._base_command_kvdb(api_socket, '', '', 'get')

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

    def _recursive_command_to_catalog(self, api_socket: str, path_str: str, type: str, command: str, namespace: str, print_name: bool = False):
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
                        api_socket, type[:-1], name, component, namespace, Format.YML, command)

    def recursive_load_catalog(self, api_socket: str, path_str: str, type: str, namespace: str, print_name: bool = False):
        self._recursive_command_to_catalog(
            api_socket, path_str, type, 'post', namespace, print_name)

    def recursive_delete_catalog(self, api_socket: str, path_str: str, type: str, namespace: str, print_name: bool = False):
        self._recursive_command_to_catalog(
            api_socket, path_str, type, 'delete', namespace, print_name)

    def get_store_integration(self, path: str, name: str, namespace: str):
        return self.get_catalog_file(path, 'integration', f'integration/{name}/0', namespace, Format.JSON)

    def _base_store_command(self, path: str, policy: str, namespaces: List[str], command: str):
        request = {'version': 1, 'command': 'policy.store/' + command, 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': {'policy': policy, 'namespaces': namespaces}}
        request_raw = json.dumps(request)
        request_bytes = len(request_raw).to_bytes(4, 'little')
        request_bytes += request_raw.encode('utf-8')
        data = b''
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            try:
                s.connect(path)
                s.sendall(request_bytes)
                data = s.recv(65507)
            except:
                raise Exception(
                    f'Could not connect and send information throug [{path}]')

        resp_size = int.from_bytes(data[:4], 'little')
        resp_message = data[4:resp_size+4].decode('UTF-8')

        # Change post for update and put for add
        if command == 'post':
            command = 'add'
        elif command == 'put':
            command = 'update'

        if not len(resp_message):
            raise Exception(
                f'Store command [{command}] received an empty response.')

        response = ''
        try:
            response = json.loads(resp_message)
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')
        if response['data']['status'] != 'OK':
            raise Exception(
                f'{response["data"]["error"]}')
        return response

    def _delete_asset(self, path: str, policy: str):
        self._base_store_command(path, policy, [], 'delete')

    def _base_asset_command(self, path: str, policy: str, namespace: str, asset: str, command: str):
        request = {'version': 1, 'command': 'policy.asset/' + command, 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': {'policy': policy, 'namespace': namespace, 'asset': asset}}
        request_raw = json.dumps(request)
        request_bytes = len(request_raw).to_bytes(4, 'little')
        request_bytes += request_raw.encode('utf-8')
        data = b''
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            try:
                s.connect(path)
                s.sendall(request_bytes)
                data = s.recv(65507)
            except:
                raise Exception(
                    f'Could not connect and send information throug [{path}]')

        resp_size = int.from_bytes(data[:4], 'little')
        resp_message = data[4:resp_size+4].decode('UTF-8')

        # Change post for update and put for add
        if command == 'post':
            command = 'add'
        elif command == 'put':
            command = 'update'

        if not len(resp_message):
            raise Exception(
                f'Asset command [{command}] received an empty response.')

        response = ''
        try:
            response = json.loads(resp_message)
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')
        if response['data']['status'] != 'OK':
            raise Exception(
                f'{response["data"]["error"]}')
        return response

    def _base_default_parent_command(self, path: str, policy: str, namespace: str, parent: str,  command: str):
        request = {'version': 1, 'command': 'policy.defaultParent/' + command, 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': {'policy': policy, 'namespace': namespace, 'parent': parent}}
        request_raw = json.dumps(request)
        request_bytes = len(request_raw).to_bytes(4, 'little')
        request_bytes += request_raw.encode('utf-8')
        data = b''
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            try:
                s.connect(path)
                s.sendall(request_bytes)
                data = s.recv(65507)
            except:
                raise Exception(
                    f'Could not connect and send information throug [{path}]')

        resp_size = int.from_bytes(data[:4], 'little')
        resp_message = data[4:resp_size+4].decode('UTF-8')

        # Change post for update and put for add
        if command == 'post':
            command = 'add'
        elif command == 'put':
            command = 'update'

        if not len(resp_message):
            raise Exception(
                f'defaultParent command [{command}] received an empty response.')

        response = ''
        try:
            response = json.loads(resp_message)
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')
        if response['data']['status'] != 'OK':
            raise Exception(
                f'{response["data"]["error"]}')
        return response

    def _get_policies_command(self, path: str):
        request = {'version': 1, 'command': 'policy.policies/get', 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': {}}
        request_raw = json.dumps(request)
        request_bytes = len(request_raw).to_bytes(4, 'little')
        request_bytes += request_raw.encode('utf-8')
        data = b''
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            try:
                s.connect(path)
                s.sendall(request_bytes)
                data = s.recv(65507)
            except:
                raise Exception(
                    f'Could not connect and send information throug [{path}]')

        resp_size = int.from_bytes(data[:4], 'little')
        resp_message = data[4:resp_size+4].decode('UTF-8')

        if not len(resp_message):
            raise Exception(
                f'Policies command [{command}] received an empty response.')

        response = ''
        try:
            response = json.loads(resp_message)
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')
        if response['data']['status'] != 'OK':
            raise Exception(
                f'{response["data"]["error"]}')
        return response

    def _list_namespaces_command(self, path: str, policy: str):
        request = {'version': 1, 'command': 'policy.namespaces/get', 'origin': {
            'name': 'engine-suite', 'module': 'engine-suite'}, 'parameters': {'policy': policy}}
        request_raw = json.dumps(request)
        request_bytes = len(request_raw).to_bytes(4, 'little')
        request_bytes += request_raw.encode('utf-8')
        data = b''
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            try:
                s.connect(path)
                s.sendall(request_bytes)
                data = s.recv(65507)
            except:
                raise Exception(
                    f'Could not connect and send information throug [{path}]')

        resp_size = int.from_bytes(data[:4], 'little')
        resp_message = data[4:resp_size+4].decode('UTF-8')

        if not len(resp_message):
            raise Exception(
                f'Namespaces command [{command}] received an empty response.')

        response = ''
        try:
            response = json.loads(resp_message)
        except:
            raise Exception(
                f'Could not parse response message "{resp_message}".')
        if response['data']['status'] != 'OK':
            raise Exception(
                f'{response["data"]["error"]}')
        return response
