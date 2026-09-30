# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Endpoint coverage guard for the API integration tests.

Every operation in `api/api/spec/spec.yaml` owes a set of cases (buckets) to the tavern suite: a
success, a 400 when it takes input, a 401, a 403 from an RBAC file when it is protected by an
action, a 404 when the spec declares one, a 405 on its path, and a 413 and a 415 when it takes a
body. This
script matches every tavern stage to the operation it calls, fills the buckets and:

- `--check` (default) exits 1 when a bucket is empty and not excepted, when an exception is stale
  or malformed, when a stage calls a route the spec does not have, or when COVERAGE.md is out of
  date.
- `--write` regenerates COVERAGE.md.

Exceptions live in coverage_exceptions.yaml, each with the reason the bucket cannot be filled.
"""

import argparse
import glob
import itertools
import re
import sys
from dataclasses import dataclass, field
from os import path

import yaml

MAPPING_DIR = path.dirname(path.abspath(__file__))
TESTS_DIR = path.dirname(MAPPING_DIR)
REPO_DIR = path.dirname(path.dirname(path.dirname(TESTS_DIR)))
SPEC_PATH = path.join(REPO_DIR, 'api', 'api', 'spec', 'spec.yaml')
EXCEPTIONS_PATH = path.join(MAPPING_DIR, 'coverage_exceptions.yaml')
REPORT_PATH = path.join(MAPPING_DIR, 'COVERAGE.md')

HTTP_METHODS = ('get', 'put', 'post', 'delete', 'patch', 'head', 'options')
GENERIC_PARAMS = {'pretty', 'wait_for_complete'}
RBAC_FILE_PREFIX = 'test_rbac_'

# Bucket -> (column title, description)
BUCKETS = {
    'ok': ('2xx', 'a success stage'),
    'bad_request': ('400', 'a 400 stage; required when the operation takes a parameter other than '
                           '`pretty`/`wait_for_complete`, or a body'),
    'unauthorized': ('401', 'a 401 stage; required for every operation with an auth scheme'),
    'forbidden': ('403', 'a 403 stage in a `test_rbac_*` file; required when the operation has '
                         '`x-rbac-actions`'),
    'not_found': ('404', 'a 404 stage; required when the spec declares 404'),
    'method_not_allowed': ('405', 'a 405 stage on the same path with an undeclared method'),
    'too_large': ('413', 'a 413 stage; required when the operation takes a body'),
    'unsupported_media_type': ('415', 'a 415 stage with a content-type the operation does not accept; required '
                                      'when the operation takes a body'),
}
STATUS_BUCKET = {400: 'bad_request', 401: 'unauthorized', 404: 'not_found', 413: 'too_large',
                 415: 'unsupported_media_type'}

URL_PREFIX_REGEX = re.compile(r'^\{protocol(:s)?\}://\{host(:s)?\}:\{[a-z_]+_port(:d)?\}')
PLACEHOLDER_REGEX = re.compile(r'\{([A-Za-z_][A-Za-z0-9_]*)(:[a-z])?\}')


class TavernLoader(yaml.SafeLoader):
    """Safe loader that keeps the line of every mapping and accepts tavern's custom tags.

    Like tavern's own loader, anchors survive across the documents of a file.
    """

    def compose_document(self):
        self.get_event()  # DocumentStart
        node = self.compose_node(None, None)
        self.get_event()  # DocumentEnd
        return node


def _construct_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = yaml.SafeLoader.construct_mapping(loader, node, deep=deep)
    mapping['__line__'] = node.start_mark.line + 1
    return mapping


def _construct_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node, deep=True)
    return _construct_mapping(loader, node, deep=True)


TavernLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
TavernLoader.add_multi_constructor('!', _construct_tag)


@dataclass
class Operation:
    method: str
    path: str
    tag: str
    required: set
    regex: re.Pattern
    literal_segments: int
    covered: dict = field(default_factory=dict)  # bucket -> set of test files

    @property
    def key(self) -> str:
        return f'{self.method} {self.path}'


@dataclass
class Stage:
    file: str
    line: int
    method: str
    url_path: str
    status_codes: tuple


def _resolve(spec: dict, item: dict) -> dict:
    """Resolve a local `$ref`."""
    ref = item.get('$ref') if isinstance(item, dict) else None
    if not ref:
        return item
    node = spec
    for part in ref.lstrip('#/').split('/'):
        node = node[part]
    return node


def _template_regex(template: str) -> re.Pattern:
    pattern = ''.join('[^/]+' if part.startswith('{') else re.escape(part)
                      for part in re.split(r'(\{[^}]+\})', template))
    return re.compile(f'^{pattern}/?$')


def load_operations(spec_path: str = SPEC_PATH) -> list:
    """Read every operation of the spec and the buckets it owes."""
    with open(spec_path) as f:
        spec = yaml.safe_load(f)

    global_security = spec.get('security', [])
    operations = []
    for op_path, path_item in spec['paths'].items():
        path_params = [_resolve(spec, p) for p in path_item.get('parameters', [])]
        for method, op in path_item.items():
            if method not in HTTP_METHODS:
                continue
            params = path_params + [_resolve(spec, p) for p in op.get('parameters', [])]
            responses = {str(code) for code in op.get('responses', {})}
            security = op.get('security', global_security)

            required = {'ok', 'method_not_allowed'}
            if any(p['name'] not in GENERIC_PARAMS for p in params) or 'requestBody' in op:
                required.add('bad_request')
            if any(scheme for scheme in security):
                required.add('unauthorized')
            if op.get('x-rbac-actions'):
                required.add('forbidden')
            if '404' in responses:
                required.add('not_found')
            if 'requestBody' in op:
                required.update({'too_large', 'unsupported_media_type'})

            operations.append(Operation(
                method=method.upper(), path=op_path, tag=(op.get('tags') or ['Untagged'])[0],
                required=required, regex=_template_regex(op_path),
                literal_segments=sum(1 for s in op_path.split('/') if s and not s.startswith('{'))))
    return operations


def _parametrize_bindings(marks: list) -> list:
    """Expand tavern `parametrize` marks into the list of variable bindings they produce."""
    axes = []
    for mark in marks or []:
        if not isinstance(mark, dict) or 'parametrize' not in mark:
            continue
        param = mark['parametrize']
        keys = param['key'] if isinstance(param['key'], list) else [param['key']]
        values = []
        for val in param['vals']:
            if isinstance(val, dict):
                val = {k: v for k, v in val.items() if k != '__line__'}
            row = val if len(keys) > 1 else [val]
            values.append(dict(zip(keys, row)))
        axes.append(values)
    if not axes:
        return [{}]
    return [dict(itertools.chain.from_iterable(b.items() for b in combo)) for combo in itertools.product(*axes)]


def _format(value: str, bindings: dict) -> str:
    def replace(match):
        name = match.group(1)
        return str(bindings[name]) if name in bindings and not isinstance(bindings[name], dict) else match.group(0)
    return PLACEHOLDER_REGEX.sub(replace, str(value))


def _status_codes(response: dict) -> tuple:
    status = (response or {}).get('status_code', 200)
    statuses = status if isinstance(status, list) else [status]
    return tuple(int(s) for s in statuses if str(s).isdigit())


def load_stages(tests_dir: str = TESTS_DIR) -> list:
    """Read every request stage of every tavern file, with parametrize marks expanded."""
    stages = []
    files = sorted(glob.glob(path.join(tests_dir, 'test_*.tavern.yaml')) +
                   glob.glob(path.join(tests_dir, '_test_*.tavern.yaml')))
    for file_path in files:
        file_name = path.basename(file_path)
        with open(file_path) as f:
            documents = [d for d in yaml.load_all(f, Loader=TavernLoader) if d]
        for document in documents:
            for bindings in _parametrize_bindings(document.get('marks')):
                for stage in document.get('stages', []):
                    request = stage.get('request') if isinstance(stage, dict) else None
                    if not request:
                        continue
                    url = URL_PREFIX_REGEX.sub('', _format(request['url'], bindings))
                    url_path = url.split('?', 1)[0] or '/'
                    method = _format(request.get('method', 'GET'), bindings).upper()
                    stages.append(Stage(file=file_name, line=stage['__line__'], method=method,
                                        url_path=url_path, status_codes=_status_codes(stage.get('response'))))
    return stages


def load_exceptions(exceptions_path: str = EXCEPTIONS_PATH) -> list:
    with open(exceptions_path) as f:
        return yaml.safe_load(f) or []


def match_path(operations: list, url_path: str) -> list:
    """Return the operations of the most specific spec path that matches `url_path`."""
    candidates = [op for op in operations if op.regex.match(url_path)]
    if not candidates:
        return []
    best = max(op.literal_segments for op in candidates)
    best_path = sorted({op.path for op in candidates if op.literal_segments == best})[0]
    return [op for op in candidates if op.path == best_path]


def evaluate(operations: list, stages: list, exceptions: list) -> list:
    """Fill the buckets of every operation. Return the list of errors found."""
    errors = []
    unknown_route_404 = 0

    for stage in stages:
        where = f'{stage.file}:{stage.line}'
        if stage.method == 'OPTIONS':
            # A CORS preflight, answered by the CORS middleware before routing: no operation is called
            continue
        path_ops = match_path(operations, stage.url_path)
        if not path_ops:
            if stage.status_codes == (404,):
                unknown_route_404 += 1
                continue
            errors.append(f'{where}: {stage.method} {stage.url_path} matches no spec path')
            continue

        op = next((o for o in path_ops if o.method == stage.method), None)
        if op is None:
            if stage.status_codes == (405,):
                for path_op in path_ops:
                    path_op.covered.setdefault('method_not_allowed', set()).add(stage.file)
            else:
                errors.append(f'{where}: {stage.method} is not declared for {path_ops[0].path}; '
                              f'only a 405 is expected there')
            continue

        if 405 in stage.status_codes:
            errors.append(f'{where}: 405 asserted on the declared operation {op.key}')
        for status in stage.status_codes:
            bucket = STATUS_BUCKET.get(status)
            if 200 <= status < 300:
                bucket = 'ok'
            elif status == 403:
                bucket = 'forbidden' if stage.file.startswith(RBAC_FILE_PREFIX) else None
            if bucket:
                op.covered.setdefault(bucket, set()).add(stage.file)

    by_key = {op.key: op for op in operations}
    seen = set()
    for exception in exceptions:
        key, bucket = exception.get('operation'), exception.get('bucket')
        label = f'exception {key!r} / {bucket!r}'
        if key not in by_key:
            errors.append(f'{label}: no such operation in the spec')
            continue
        if bucket not in BUCKETS:
            errors.append(f'{label}: unknown bucket (one of {", ".join(BUCKETS)})')
            continue
        if not str(exception.get('reason', '')).strip():
            errors.append(f'{label}: a reason is required')
        if (key, bucket) in seen:
            errors.append(f'{label}: duplicated')
        seen.add((key, bucket))
        op = by_key[key]
        if bucket not in op.required:
            errors.append(f'{label}: stale, the bucket is not required for this operation')
        elif bucket in op.covered:
            errors.append(f'{label}: stale, covered by {", ".join(sorted(op.covered[bucket]))}')

    for op in operations:
        for bucket in sorted(op.required - set(op.covered)):
            if (op.key, bucket) not in seen:
                errors.append(f'{op.key}: missing {BUCKETS[bucket][1]}')

    return errors


def render_report(operations: list, exceptions: list) -> str:
    """Render COVERAGE.md."""
    excepted = {(e['operation'], e['bucket']): e for e in exceptions}
    lines = [
        '# API integration test coverage',
        '',
        '<!-- Generated by `python3 endpoint_coverage.py --write`. Do not edit by hand: `--check` fails when this',
        '     file differs from what the tavern files and spec.yaml produce. -->',
        '',
        'One row per operation of `api/api/spec/spec.yaml`, one column per case the operation owes to '
        'the tavern suite in `api/test/integration/`.',
        '',
        '| Mark | Meaning |',
        '|---|---|',
        '| ✓ | covered |',
        '| ✗ | required and missing (fails `--check`) |',
        '| pending | missing, listed as a temporary exception in `coverage_exceptions.yaml` |',
        '| waived | cannot be covered, listed with its reason in `coverage_exceptions.yaml` |',
        '| · | not required |',
        '',
        '| Bucket | Required |',
        '|---|---|',
    ]
    lines += [f'| {title} | {description} |' for title, description in BUCKETS.values()]

    total = {bucket: [0, 0] for bucket in BUCKETS}
    for op in operations:
        for bucket in op.required:
            total[bucket][1] += 1
            total[bucket][0] += bucket in op.covered
    lines += ['', '## Summary', '', f'{len(operations)} operations.', '',
              '| Bucket | Covered | Required |', '|---|---|---|']
    lines += [f'| {BUCKETS[b][0]} | {c} | {r} |' for b, (c, r) in total.items()]

    tags = []
    for op in operations:
        if op.tag not in tags:
            tags.append(op.tag)
    header = '| Operation | ' + ' | '.join(title for title, _ in BUCKETS.values()) + ' | Test files |'
    separator = '|---|' + '---|' * (len(BUCKETS) + 1)
    for tag in tags:
        lines += ['', f'## {tag}', '', header, separator]
        for op in (o for o in operations if o.tag == tag):
            cells = []
            for bucket in BUCKETS:
                exception = excepted.get((op.key, bucket))
                if bucket not in op.required:
                    cells.append('·')
                elif bucket in op.covered:
                    cells.append('✓')
                elif exception:
                    cells.append('pending' if exception.get('pending') else 'waived')
                else:
                    cells.append('✗')
            files = sorted(set().union(*op.covered.values())) if op.covered else []
            short = ', '.join(f.removeprefix('test_').removesuffix('.tavern.yaml') for f in files)
            lines.append(f'| `{op.key}` | ' + ' | '.join(cells) + f' | {short or "—"} |')
    return '\n'.join(lines) + '\n'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='Check the coverage and COVERAGE.md (the default).')
    mode.add_argument('--write', action='store_true', help='Regenerate COVERAGE.md.')
    args = parser.parse_args()

    operations = load_operations()
    exceptions = load_exceptions()
    errors = evaluate(operations, load_stages(), exceptions)
    report = render_report(operations, exceptions)

    if args.write:
        with open(REPORT_PATH, 'w') as f:
            f.write(report)
        print(f'{path.relpath(REPORT_PATH, REPO_DIR)} written.')
    else:
        try:
            with open(REPORT_PATH) as f:
                current = f.read()
        except FileNotFoundError:
            current = None
        if current != report:
            errors.append(f'{path.relpath(REPORT_PATH, REPO_DIR)} is out of date: run '
                          f'`python3 {path.relpath(__file__, REPO_DIR)} --write`')

    for error in errors:
        print(f'ERROR: {error}', file=sys.stderr)
    if errors:
        print(f'{len(errors)} coverage error(s).', file=sys.stderr)
        return 1
    print(f'Coverage OK: {len(operations)} operations.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
