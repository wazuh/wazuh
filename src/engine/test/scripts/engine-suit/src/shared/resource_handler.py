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


class ResourceHandler:
    def __init__(self):
        self._files = files('engine-suit')

    def _read_json(self, content: str) -> dict:
        return json.loads(content)

    def _read_yml(self, content: str) -> dict:
        return yaml.load(content, Loader=Loader)

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
            content_str = yaml.dump(content, Dumper=Dumper)
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
            raise Exception(f'Failed to read {full_name}')

        return readed

    def _load_file(self, path: Path, format: Format = Format.YML) -> dict:
        content = path.read_text()

        readed = self._read(content, format)
        if not readed:
            raise Exception(f'Failed to read {full_name}')

        return readed

    def load_file(self, path_str: str, format: Format = Format.YML) -> dict:
        path = Path(path_str)
        return self._load_file(path, format)

    def load_module_files(self, root_dir: str, module_name: str) -> Tuple[dict, dict]:
        module_path = Path(root_dir)/module_name
        fields_definition = self._load_file(
            module_path/'fields.yml', Format.YML)
        logpar_overrides = None
        logpar_path = module_path/'logpar.json'
        if logpar_path.exists():
            logpar_overrides = self._load_file(logpar_path, Format.JSON)

        return fields_definition, logpar_overrides

    def save_file(self, path_str: str, name: str, content: dict, format: Format):
        path = Path(path_str)
        path.mkdir(parents=True, exist_ok=True)
        pure_path = PurePath(path / name)

        self._write_file(pure_path, content, format)

    def update_catalog_file(self, path: str, name: str, content: dict, format: Format):
        # TODO Update once API refactored is implemented
        raw_message = ''
        format_str = ''
        if format is Format.JSON:
            raw_message = json.dumps(content)
            format_str = 'json'
        elif format is Format.YML:
            raw_message = yaml.dump(content, Dumper=Dumper)
            format_str = 'yaml'
        else:
            raise Exception(f'Format not supported in update catalog {name}')

        request = {'version': 1, 'command': 'put_catalog', 'origin': {
            'name': 'engine-schema', 'module': 'engine-schema'}, 'parameters': {'name': name, 'content': raw_message, 'format': format_str}}
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

        response = json.loads(resp_message)
        if response['message'] != 'OK':
            raise Exception(
                f'Could not update {name} due to: {response["message"]}')
