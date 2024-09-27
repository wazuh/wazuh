import sys
import json
import yaml
from pathlib import Path

INTEGRATION_WITHOUT_TESTS = 'wazuh-core'

def find_and_collect_assets(directory):
    """Recursively search for .yml files, read the 'name' key, and add it to a list."""
    names = []
    for yml_file in Path(directory).rglob('*.yml'):
        if INTEGRATION_WITHOUT_TESTS in yml_file.parts:
            continue

        try:
            with yml_file.open('r') as file:
                if yml_file.name == 'custom_fields.yml':
                    continue
                yml_content = yaml.safe_load(file)
                name = yml_content.get('name').split('/')[1]
                if name:
                    names.append(name)
        except yaml.YAMLError as exc:
            print(f"Error reading file {yml_file}: {exc}")
    return names

def verify_event_processing(all_assets: dict, expected_json_files):
    """
    Compare the assets in 'wazuh.decoders' in the '_expected.json' files with the list of all_assets.
    Each found asset is removed from the all_assets list. If assets remain at the end, the test fails.
    """
    for json_file in expected_json_files:
        try:
            with open(json_file, 'r') as f:
                expected_data = json.load(f)
                for expected in expected_data:
                    decoders = expected.get('wazuh', {}).get('decoders', [])
                    for decoder in decoders:
                        if decoder in all_assets['decoders']:
                            all_assets['decoders'].remove(decoder)

                    rules = expected.get('wazuh', {}).get('rules', [])
                    for rule in rules:
                        if rule in all_assets['rules']:
                            all_assets['rules'].remove(rule)
        except Exception as e:
            sys.exit(f"Error reading the file '{json_file}': {e}")

def find_expected_json_files(test_folder):
    return list(test_folder.rglob('*_expected.json'))

def verify(all_assets: dict, ruleset_path: Path):
    integrations_path = ruleset_path / 'integrations'
    if not integrations_path.exists() or not integrations_path.is_dir():
        sys.exit(f"Error: '{integrations_path}' directory does not exist or not found.")

    for integration in integrations_path.iterdir():
        if not integration.is_dir():
            continue

        if integration.name != INTEGRATION_WITHOUT_TESTS:
            test_folder = integration / 'test'
            if not test_folder.exists() or not test_folder.is_dir():
                sys.exit(f"No 'test' folder found in '{integration}'.")

            expected_json_files = find_expected_json_files(test_folder)
            if not expected_json_files:
                sys.exit(f"No '_expected.json' files found in '{test_folder}' or its subfolders.")
            
            verify_event_processing(all_assets, expected_json_files)
    
    rules_path = ruleset_path / 'rules'
    if not rules_path.exists() or not rules_path.is_dir():
        sys.exit(f"Error: '{rules_path}' directory does not exist or not found.")

    for rule_folder in rules_path.iterdir():
        if not integration.is_dir():
            continue

        if rule_folder.name != INTEGRATION_WITHOUT_TESTS:
            test_folder = rule_folder / 'test'
            if not test_folder.exists() or not test_folder.is_dir():
                sys.exit(f"No 'test' folder found in '{integration}'.")

            expected_json_files = find_expected_json_files(test_folder)
            if not expected_json_files:
                sys.exit(f"No '_expected.json' files found in '{test_folder}' or its subfolders.")
            
            verify_event_processing(all_assets, expected_json_files)

    missing_assets = []
    if all_assets['decoders']:
        missing_assets.append(f"These assets were not found in 'wazuh.decoders': {', '.join(all_assets['decoders'])}")
    if all_assets['rules']:
        missing_assets.append(f"These assets were not found in 'wazuh.rules': {', '.join(all_assets['rules'])}")

    if missing_assets:
        print("Test failed.\n" + "\n".join(missing_assets))
        sys.exit(1)

def validator(ruleset_path: Path):
    decoders_path = ruleset_path / 'decoders'
    if not decoders_path.exists() or not decoders_path.is_dir():
        sys.exit(f"Error: '{decoders_path}' directory does not exist or not found.")

    rules_path = ruleset_path / 'rules'
    if not rules_path.exists() or not rules_path.is_dir():
        sys.exit(f"Error: '{rules_path}' directory does not exist or not found.")

    decoder_list = find_and_collect_assets(decoders_path)
    rules_list = find_and_collect_assets(rules_path)

    all_assets = {
        'decoders': decoder_list,
        'rules': rules_list
    }
    verify(all_assets, ruleset_path)


def run(args):
    ruleset_path = Path(args['ruleset']).resolve()

    if not ruleset_path.is_dir():
        sys.exit(f"Engine ruleset not found: {ruleset_path}")

    try:
        print("Running event processing tests.")
        validator(ruleset_path)
        print("Success execution")
    except Exception as e:
        sys.exit(f"Error running test: {e}")
