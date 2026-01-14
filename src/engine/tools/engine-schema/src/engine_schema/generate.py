from typing import Tuple
from copy import deepcopy
import os
import tempfile
from pathlib import Path

from . import resource_handler as rs

from .drivers import ecs




def _merge_yaml_dicts(dict1: dict, dict2: dict) -> dict:
    """
    Deep merge two dictionaries, avoiding key duplication.
    If a key exists in both dictionaries and both values are dictionaries,
    they are merged recursively. Otherwise, dict2's value takes precedence.
    """
    result = deepcopy(dict1)

    for key, value in dict2.items():
        if key in result:
            if isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = _merge_yaml_dicts(result[key], value)
            else:
                result[key] = deepcopy(value)
        else:
            result[key] = deepcopy(value)

    return result


def _yaml_dict_to_file(yml_files: dict, resource_handler: rs.ResourceHandler) -> str:
    """
    Saves a YAML dictionary to a temporary file and returns the file path.
    """
    merged_data = {}
    for yml_file in sorted(yml_files):
        print(f"Loading {yml_file.name}...")
        try:
            file_data = resource_handler.load_file(str(yml_file), rs.Format.YML)
            merged_data = _merge_yaml_dicts(merged_data, file_data)
        except Exception as e:
            print(f"Error loading {yml_file.name}: {e}")
            raise

    # Temporary file
    temp_fd, temp_path = tempfile.mkstemp(suffix='.yml', prefix='merged_wcs_')

    try:
        resource_handler.save_file(os.path.dirname(temp_path), os.path.basename(temp_path), merged_data, rs.Format.YML)
        os.close(temp_fd)
        print(f"Successfully merged {len(yml_files)} files into temporary file: {temp_path}")
        return temp_path
    except Exception as e:
        os.close(temp_fd)
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise e


def _merge_yaml_files_in_directory(directory_path: str, resource_handler: rs.ResourceHandler) -> str:
    """
    Merges all .yml files in a directory into a single temporary file.
    """
    dir_path = Path(directory_path)

    if not dir_path.exists() or not dir_path.is_dir():
        raise ValueError(f"Directory does not exist or is not a directory: {directory_path}")

    yml_files = list(dir_path.glob("*.yml")) + list(dir_path.glob("*.yaml"))
    if not yml_files:
        raise ValueError(f"No .yml or .yaml files found in directory: {directory_path}")
    print(f"Found {len(yml_files)} YAML files to merge: {[f.name for f in yml_files]}")

    return _yaml_dict_to_file(yml_files, resource_handler)


def _merge_yaml_files_from_list(file_paths_str: str, resource_handler: rs.ResourceHandler) -> str:
    """
    Merges YAML files from a comma-separated list of file paths into a single temporary file.
    """
    # Split and clean the file paths
    file_paths = [path.strip() for path in file_paths_str.split(',') if path.strip()]

    if not file_paths:
        raise ValueError("No valid file paths provided in comma-separated list")

    # Convert to Path objects and validate
    yml_files = []
    for file_path in file_paths:
        path_obj = Path(file_path)
        if not path_obj.exists():
            raise ValueError(f"File does not exist: {file_path}")
        if not path_obj.is_file():
            raise ValueError(f"Path is not a file: {file_path}")
        if path_obj.suffix.lower() not in ['.yml', '.yaml']:
            raise ValueError(f"File is not a YAML file: {file_path}")
        yml_files.append(path_obj)

    print(f"Found {len(yml_files)} YAML files to merge: {[f.name for f in yml_files]}")

    return _yaml_dict_to_file(yml_files, resource_handler)


def _build_fields_schema(base_template: dict, properties: dict, file_id: str, name: str) -> dict:
    t = deepcopy(base_template)
    t['$id'] = file_id            # p.ej. "rule_fields.json" or "decoder_fields.json"
    t['name'] = name              # p.ej. "schema/rule-fields/0"
    t['properties'] = properties  # filtered tree
    return t


def generate(wcs_path: str, resource_handler: rs.ResourceHandler) -> Tuple[dict, dict, dict, dict]:

    print('Loading resources...')
    temp_file_path = None
    try:
        # Check wcs_path for single file, comma-separated files or directory
        if ',' in wcs_path:
            print(f'Loading WCS files from comma-separated list: {wcs_path}...')
            temp_file_path = _merge_yaml_files_from_list(wcs_path, resource_handler)
            wcs_flat = resource_handler.load_file(temp_file_path)
        else:
            wcs_path_obj = Path(wcs_path)
            if wcs_path_obj.is_dir():
                print(f'Loading WCS files from directory {wcs_path}...')
                temp_file_path = _merge_yaml_files_in_directory(wcs_path, resource_handler)
                wcs_flat = resource_handler.load_file(temp_file_path)
            else:
                print(f'Loading WCS file from {wcs_path}...')
                wcs_flat = resource_handler.load_file(wcs_path)

        print(f'Loading schema template...')
        fields_template = resource_handler.load_internal_file('fields.template')
        print(f'Loading logpar overrides template...')
        logpar_template = resource_handler.load_internal_file('logpar_types')

        # Generate field tree from ecs_flat
        print('Building field tree from WCS definition...')
        field_tree = ecs.build_field_tree(wcs_flat)
        field_tree.add_logpar_overrides(logpar_template["fields"])
        print('Success.')

        # Engine schema
        print('Generating engine schema...')
        engine_schema = dict()
        engine_schema['name'] = 'schema/engine-schema/0'
        engine_schema['fields'] = dict()
        engine_schema['fields'] = ecs.to_engine_schema(wcs_flat)

        # Get schema properties
        print('Generating fields schema properties...')
        jproperties = field_tree.get_jschema()

        # Build unified schema with all fields (no partition)
        decoder_fields_schema = _build_fields_schema(fields_template, jproperties,
                                                     file_id='fields_decoder.json',
                                                     name='schema/fields-decoder/0')
        print('Success.')

        # Build a clean properties mapping
        print('Generating clean properties mapping...')
        jmappings = field_tree.get_jmapping()
        mappings_properties = {"properties": jmappings}
        print('Success.')

        # Get the logpar configuration file
        print('Generating logpar configuration...')
        logpar_template["fields"] = field_tree.get_jlogpar()
        print('Success.')

        return decoder_fields_schema, mappings_properties, logpar_template, engine_schema

    finally:
        # Clean up temporary file if it was created
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
                print(f'Cleaned up temporary file: {temp_file_path}')
            except Exception as e:
                print(f'Warning: Could not delete temporary file {temp_file_path}: {e}')
