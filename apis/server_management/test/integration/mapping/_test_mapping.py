# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import glob
import json
import re
import sys
from collections import defaultdict
from copy import copy
from os import chdir, path, walk

base = path.dirname(path.dirname(path.dirname(path.dirname(path.dirname(path.abspath(__file__))))))
framework = path.join(base, 'framework', 'wazuh')
api = path.join(base, 'api', 'api')
integration_tests = path.join(base, 'api', 'test', 'integration')

# Mapping file
file_path = path.join(integration_tests, 'mapping', 'integration_test_api_endpoints.json')

# Wazuh modules
wazuh_modules = [
    api,  # API
    framework,  # SDK, CORE and RBAC (recursive call)
    integration_tests  # Integration tests
]

file_tag_regex = re.compile(r'([^_]+).*\.[a-z]{2,4}')
test_tag_regex = re.compile(r'test_([^_]+).*.yaml')
allowed_extensions = ('.py', '.yaml', '.sql', '.yml', '.sh')


def calculate_test_mappings():
    chdir(integration_tests)
    test_mapping = defaultdict(list)

    for test in sorted(glob.glob('test_*.yaml')):
        test_tag = re.match(test_tag_regex, test).group(1)
        if test_tag.startswith('rbac'):
            # Add RBAC tests
            test_mapping['rbac'].append(test)
        else:
            # Add every other test
            test_mapping[test_tag.lower()].append(test)

    # Create custom tag for basic tests
    for test in sorted(
            [tests for tests in map(lambda x: test_mapping[x], ['agent', 'cluster'])]):
        test_mapping['basic'].extend(test)

    return test_mapping

def extract_module_from_path(file_path):
    """Extracts the module from the file path."""
    parts = file_path.split('/')
    # Assuming the module is the last part of the path
    wazuh_modules = parts[-1]
    return wazuh_modules

def get_file_and_test_info(test_name, test_mapping, module_name):
    try:
        # Get file tag, i.e.: agent.py -> agent
        test_tag = re.match(file_tag_regex, test_name.lower()).group(1)
    except AttributeError:
        return None

    if test_tag == 'test':
        # Integration tests themselves must be added. Unit tests must not
        related_tests = [test_name] if test_name.endswith('.yaml') else []
    elif path.basename(module_name) == 'rbac':
        # Every file within the RBAC directory must be tagged as RBAC
        related_tests = test_mapping['rbac']
    elif test_tag in ['black', 'white']:
        # If the tag contains 'black' or 'white', filter RBAC tests with the same tag
        module_name = extract_module_from_path(mappings['path'])
        related_tests = [test for test in test_mapping['rbac'] if test_tag in test and module_name in test]
    elif test_mapping[test_tag]:
        # If a tag matches, both their normal and RBAC tests will be assigned
        related_tests = test_mapping[test_tag] + [test for test in test_mapping['rbac'] if test_tag in test] \
            if test_tag != 'rbac' else test_mapping[test_tag]
    else:
        # If no tag is matched, basic tests will be assigned
        related_tests = test_mapping['basic']

    return [test_name, test_tag, sorted(related_tests)]


if __name__ == '__main__':
    # Generate mapping file
    if len(sys.argv) == 1:
        test_tags = calculate_test_mappings()

        mapping_list = list()
        for module in wazuh_modules:
            chdir(module)
            for root, dirs, files in sorted(walk('.')):
                mappings = dict()
                mappings['path'] = path.join(path.relpath(module, base), root.lstrip('./')).strip('/')
                mappings['files'] = list()
                for file in sorted(files):
                    if file.endswith(allowed_extensions):
                        test_info = get_file_and_test_info(file, test_tags, module)
                        if test_info and test_info[2]:
                            mappings['files'].append({'name': test_info[0], 'tag': test_info[1], 'tests': test_info[2]})

                mappings['files'] and mapping_list.append(copy(mappings))

        with open(file_path, 'w') as f:
            f.write(json.dumps(mapping_list, indent=4))

        print(f'Test mappings file generated at {file_path}')
    # Calculate mappings for a given file
    elif len(sys.argv) == 2:
        if not path.exists(file_path):
            print('Test mapping file does not exist. Run this script without any argument to generate it.')
            exit(0)
        file_rel_path = sys.argv[1]

        if not path.exists(path.join(base, file_rel_path)):
            print('The relative path does not exist. Example: "framework/wazuh/agent.py"')
            exit(0)

        with open(file_path) as f:
            mappings = json.loads(f.read())
        file_path = path.dirname(file_rel_path)
        file_name = path.basename(file_rel_path)

        match = next((item for item in mappings if item['path'] == file_path), None)
        if not match:
            print('That file is not mapped.')
            exit(0)

        files = next((item['tests'] for item in match['files'] if item['name'] == file_name), [])
        print('No tests assigned to that file' if not files else '\n'.join(files))
    else:
        print('Invalid number of arguments.\n\t- No arguments: generate test mapping file.\n\t- One argument: '
              'Show assigned integration tests to that file.')
        