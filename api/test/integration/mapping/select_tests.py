# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Select the API integration test files a set of changed files can affect.

Prints the JSON list the test matrix of 5_testintegration_api-endpoints.yml consumes; why each
changed file selected what it did goes to stderr.

    python3 select_tests.py --base origin/5.0.0        # changes since the merge-base with the base
    python3 select_tests.py --files a.py b/c.yaml      # explicit changed files
    python3 select_tests.py --all                      # every test file
    python3 select_tests.py --test-list agent_GET,cluster   # names without test_ / .tavern.yaml
    python3 select_tests.py --check                    # validate rules, groups and workflow paths
"""

import argparse
import fnmatch
import glob
import json
import re
import subprocess
import sys
from functools import lru_cache
from os import path

import yaml

MAPPING_DIR = path.dirname(path.abspath(__file__))
TESTS_DIR = path.dirname(MAPPING_DIR)
REPO_DIR = path.dirname(path.dirname(path.dirname(TESTS_DIR)))
RULES_PATH = path.join(MAPPING_DIR, 'selection_rules.yaml')
WORKFLOW_PATH = path.join(REPO_DIR, '.github', 'workflows', '5_testintegration_api-endpoints.yml')
TESTS_REL_DIR = path.relpath(TESTS_DIR, REPO_DIR)

GROUP_REGEX = re.compile(r'^test_(?P<group>.+?)(_(GET|POST|PUT|DELETE))?_endpoints\.tavern\.yaml$')
SPECIAL = ('none', 'self', 'all')


@lru_cache(maxsize=None)
def glob_to_regex(pattern: str) -> re.Pattern:
    """Translate a GitHub `paths:` glob into a regex.

    `**` matches any characters including `/` (`**/` also matches no directory at all), `*`
    matches any characters but `/`, `?` matches one character but `/`. Brace expansion is not
    supported by the workflow filter this mirrors, so it is refused rather than misread.
    """
    if '{' in pattern or '}' in pattern:
        raise ValueError(f'Brace expansion is not supported: {pattern!r}')
    regex, i = '', 0
    while i < len(pattern):
        if pattern.startswith('**/', i):
            regex, i = regex + '(?:.*/)?', i + 3
        elif pattern.startswith('**', i):
            regex, i = regex + '.*', i + 2
        elif pattern[i] == '*':
            regex, i = regex + '[^/]*', i + 1
        elif pattern[i] == '?':
            regex, i = regex + '[^/]', i + 1
        else:
            regex, i = regex + re.escape(pattern[i]), i + 1
    return re.compile(f'^{regex}$')


def matches(pattern: str, file: str) -> bool:
    return bool(glob_to_regex(pattern).match(file))


def load_workflow_paths(workflow_path: str = WORKFLOW_PATH) -> list:
    with open(workflow_path) as f:
        workflow = yaml.safe_load(f)
    # PyYAML reads the `on` key as the boolean True
    triggers = workflow.get('on', workflow.get(True))
    return triggers['pull_request']['paths']


def triggers_workflow(file: str, workflow_paths: list) -> bool:
    """Whether GitHub runs the workflow for `file`: the last matching pattern decides."""
    included = False
    for pattern in workflow_paths:
        negated = pattern.startswith('!')
        if matches(pattern.lstrip('!'), file):
            included = not negated
    return included


def load_rules(rules_path: str = RULES_PATH) -> list:
    with open(rules_path) as f:
        return yaml.safe_load(f)['rules']


def load_groups(tests_dir: str = TESTS_DIR) -> dict:
    """Return {group: [test files]} for every test_*.tavern.yaml file."""
    groups = {}
    for file in sorted(glob.glob(path.join(tests_dir, 'test_*.tavern.yaml'))):
        name = path.basename(file)
        match = GROUP_REGEX.match(name)
        if not match:
            raise ValueError(f'{name} does not follow test_<group>[_<METHOD>]_endpoints.tavern.yaml')
        groups.setdefault(match.group('group'), []).append(name)
    return groups


def expand_groups(patterns: list, groups: dict) -> set:
    return {test for pattern in patterns for group, tests in groups.items()
            if fnmatch.fnmatchcase(group, pattern) for test in tests}


def match_rule(file: str, rules: list):
    return next((rule for rule in rules if any(matches(p, file) for p in rule['paths'])), None)


def select(files: list, rules: list, groups: dict, workflow_paths: list, log=None) -> list:
    """Return the sorted test files the changed `files` select."""
    all_tests = {t for tests in groups.values() for t in tests}
    selected = set()
    for file in files:
        if not triggers_workflow(file, workflow_paths):
            reason, tests = 'outside the workflow paths', set()
        else:
            rule = match_rule(file, rules)
            if rule is None:
                reason, tests = 'no rule, fail-safe', all_tests
            elif rule['tests'] == 'none':
                reason, tests = rule['name'], set()
            elif rule['tests'] == 'self':
                name = path.basename(file)
                reason, tests = rule['name'], {name} & all_tests
            elif rule['tests'] == 'all':
                reason, tests = rule['name'], all_tests
            else:
                reason, tests = rule['name'], expand_groups(rule['tests'], groups)
        if log:
            summary = 'all' if tests == all_tests and tests else (', '.join(sorted(tests)) or 'nothing')
            log(f'{file}: {reason} -> {summary}')
        selected |= tests
    return sorted(selected)


def validate(rules: list, groups: dict, workflow_paths: list, tracked_files: list) -> list:
    """Check the rules against the test files, the workflow paths and the tracked files."""
    errors = []
    for rule in rules:
        tests = rule.get('tests')
        if not rule.get('name') or not rule.get('paths'):
            errors.append(f'rule {rule!r}: a name and paths are required')
            continue
        if not (tests in SPECIAL or (isinstance(tests, list) and tests)):
            errors.append(f'rule {rule["name"]!r}: tests must be none, self, all or a list of groups')
        if isinstance(tests, list):
            for pattern in tests:
                if not any(fnmatch.fnmatchcase(group, pattern) for group in groups):
                    errors.append(f'rule {rule["name"]!r}: {pattern!r} matches no test group')
        for pattern in rule['paths']:
            if not any(matches(pattern, file) for file in tracked_files):
                errors.append(f'rule {rule["name"]!r}: {pattern!r} matches no tracked file')

    # Every group must be reachable by a rule of its own, not only through `all`.
    referenced = [p for rule in rules if isinstance(rule.get('tests'), list) for p in rule['tests']]
    for group in groups:
        if not any(fnmatch.fnmatchcase(group, pattern) for pattern in referenced):
            errors.append(f'test group {group!r} is selected by no rule; add one to {path.basename(RULES_PATH)}')

    for file in tracked_files:
        in_workflow = triggers_workflow(file, workflow_paths)
        rule = match_rule(file, rules)
        if in_workflow and rule is None:
            errors.append(f'{file}: triggers the workflow but matches no rule')
        elif not in_workflow and rule is not None and rule['tests'] != 'none':
            errors.append(f'{file}: rule {rule["name"]!r} selects tests for it, but the workflow '
                          f'paths do not trigger on it')
    return errors


def tracked_files() -> list:
    output = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard'], cwd=REPO_DIR, text=True)
    return output.splitlines()


def changed_files(base: str) -> list:
    """Files changed since the merge-base with `base`, both sides of every rename."""
    merge_base = subprocess.check_output(['git', 'merge-base', base, 'HEAD'], cwd=REPO_DIR, text=True).strip()
    output = subprocess.check_output(['git', 'diff', '--name-status', '-M', f'{merge_base}...HEAD'],
                                     cwd=REPO_DIR, text=True)
    files = []
    for line in output.splitlines():
        files.extend(line.split('\t')[1:])
    return files


def resolve_test_list(names: str, groups: dict) -> list:
    """Validate `workflow_dispatch` names (no test_ prefix, no .tavern.yaml suffix, any case)."""
    all_tests = {t.lower(): t for tests in groups.values() for t in tests}
    selected = []
    for name in (n.strip() for n in names.split(',') if n.strip()):
        test = all_tests.get(f'test_{name}.tavern.yaml'.lower())
        if test is None:
            raise ValueError(f'test_{name}.tavern.yaml is not a test file')
        selected.append(test)
    return sorted(set(selected))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--base', help='Select from the changes since the merge-base with this ref.')
    mode.add_argument('--files', nargs='+', help='Select from these changed files.')
    mode.add_argument('--all', action='store_true', help='Select every test file.')
    mode.add_argument('--test-list', help='Comma-separated names without test_ and .tavern.yaml.')
    mode.add_argument('--check', action='store_true', help='Validate the rules.')
    args = parser.parse_args()

    rules, groups, workflow_paths = load_rules(), load_groups(), load_workflow_paths()
    log = lambda message: print(message, file=sys.stderr)

    if args.check:
        errors = validate(rules, groups, workflow_paths, tracked_files())
        for error in errors:
            print(f'ERROR: {error}', file=sys.stderr)
        if errors:
            return 1
        print(f'Selection rules OK: {len(rules)} rules, {len(groups)} test groups.')
        return 0

    if args.all:
        selected = sorted(t for tests in groups.values() for t in tests)
    elif args.test_list is not None:
        try:
            selected = resolve_test_list(args.test_list, groups) or sorted(t for ts in groups.values() for t in ts)
        except ValueError as e:
            print(f'ERROR: {e}', file=sys.stderr)
            return 1
    else:
        files = args.files if args.files else changed_files(args.base)
        selected = select(files, rules, groups, workflow_paths, log=log)
    print(json.dumps(selected))
    return 0


if __name__ == '__main__':
    sys.exit(main())
