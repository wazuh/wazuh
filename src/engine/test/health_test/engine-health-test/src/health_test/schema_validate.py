import sys
import json
from pathlib import Path
import shared.resource_handler as rs
from health_test.error_managment import ErrorReporter
import ipaddress
from datetime import datetime
import re


def _is_numeric_string_timestamp(value: str) -> bool:
    """Return True if value is a plain integer string (optional sign)."""
    if not isinstance(value, str):
        return False
    trimmed = value.strip()
    return bool(trimmed) and re.fullmatch(r"[+-]?\d+", trimmed) is not None


def is_valid_temporal_field(value, *, accept_numeric_string: bool, max_fraction_digits: int) -> bool:
    """
    Shared validator for date/date_nanos.
    Accepts ints, optional numeric strings (when enabled), and ISO-8601 strings with bounded fraction length.
    """
    if isinstance(value, int) and not isinstance(value, bool):
        return True

    if accept_numeric_string and _is_numeric_string_timestamp(value):
        return True

    if not isinstance(value, str):
        return False

    candidate = value.strip()
    iso_timestamp_match = re.fullmatch(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?([Zz]|[+-]\d{2}:\d{2}|[+-]\d{4})?",
        candidate
    )
    if not iso_timestamp_match:
        return False

    base, fraction, tz = iso_timestamp_match.groups()
    tz = tz or "Z"
    if tz and len(tz) == 5 and tz[0] in '+-' and ':' not in tz:
        tz = f"{tz[:3]}:{tz[3:]}"
    if fraction and len(fraction) > max_fraction_digits:
        return False

    # Normalize to microsecond precision just for parsing (we don't mutate the original value).
    normalized_fraction = (fraction or "")
    if normalized_fraction:
        normalized_fraction = (normalized_fraction + "000000")[:6]
        normalized = f"{base}.{normalized_fraction}{tz}"
    else:
        normalized = f"{base}{tz}"

    try:
        datetime.fromisoformat(normalized.replace("Z", "+00:00").replace("z", "+00:00"))
        return True
    except ValueError:
        return False


def is_valid_date(value):
    return is_valid_temporal_field(value, accept_numeric_string=True, max_fraction_digits=9)


is_valid_date_nanos = is_valid_date


def is_valid_ip(value):
    """ Check if the value is a valid IP address. """
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def infer_type_name_for_error(v, declared_elem_type: str) -> str:
    """Best-effort mapping from JSON value to an engine schema-ish type name for error messages."""
    if isinstance(v, bool):
        return 'boolean'
    if isinstance(v, int) and not isinstance(v, bool):
        return 'long'
    if isinstance(v, float):
        return 'double'
    if isinstance(v, dict):
        return 'object'
    if isinstance(v, list):
        return 'array'
    if isinstance(v, str):
        return 'keyword'
    return 'unknown'

def get_validation_function(field_type):
    """
    Returns a validator for a single element (scalar) of the declared type.
    Cardinality (scalar vs array) is handled by the caller.
    """
    if field_type in {'object', 'nested', 'flattened'}:
        return lambda v: isinstance(v, dict)

    if field_type == 'ip':
        return is_valid_ip

    if field_type in {'keyword', 'text', 'wildcard'}:
        return lambda v: isinstance(v, str)

    if field_type == 'unsigned_long':
        return lambda v: (isinstance(v, int) and not isinstance(v, bool) and v >= 0)

    if field_type in {'long', 'integer', 'short', 'byte'}:
        return lambda v: isinstance(v, int) and not isinstance(v, bool)

    if field_type in {'float', 'half_float', 'double', 'scaled_float'}:
        return lambda v: (isinstance(v, float) or (isinstance(v, int) and not isinstance(v, bool)))

    if field_type == 'boolean':
        return lambda v: isinstance(v, bool)

    if field_type == 'date':
        return is_valid_date

    if field_type == 'date_nanos':
        return is_valid_date_nanos

    if field_type == 'geo_point':

        def _is_geo_point(v):
            # 1. String "lat,lon"
            if isinstance(v, str):
                # geohash (alphanumeric without comma, from 1 to 12 chars)
                if re.fullmatch(r"[0-9a-z]+", v, re.IGNORECASE):
                    return True
                # WKT POINT (lon lat)
                if re.fullmatch(r"POINT\s*\(\s*-?\d+(\.\d+)?\s+-?\d+(\.\d+)?\s*\)", v.strip(), re.IGNORECASE):
                    return True
                # "lat,lon"
                if re.fullmatch(r"-?\d+(\.\d+)?\s*,\s*-?\d+(\.\d+)?", v.strip()):
                    return True
                return False

            # 2. Object with lat/lon
            if isinstance(v, dict):
                if "lat" in v and "lon" in v and \
                isinstance(v["lat"], (int, float)) and \
                isinstance(v["lon"], (int, float)):
                    return True
                # 3. GeoJSON
                if v.get("type") == "Point" and \
                isinstance(v.get("coordinates"), (list, tuple)) and \
                len(v["coordinates"]) == 2 and \
                all(isinstance(x, (int, float)) for x in v["coordinates"]):
                    return True
                return False

            # 4. List/tuple [lon, lat]
            if isinstance(v, (list, tuple)) and len(v) == 2 and \
            all(isinstance(x, (int, float)) for x in v):
                return True

            return False

        return _is_geo_point

    return lambda value: False

def is_template_file(custom_fields_data: list) -> bool:
    """
    Check if the given custom fields data is a template file.
    """
    if len(custom_fields_data) == 1:
        item = custom_fields_data[0]
        field_name = (item.get('field') or '').strip()
        ftype = (item.get('type') or '').strip()
        if field_name == "" and ftype == "":
            return True
    return False

def _format_yaml_parse_error(raw_msg: str, file_path: str) -> str:
    """
    Produce a concise, user-friendly YAML error message.
    Extracts 'line X, column Y' when present.
    """
    line_candidates = [int(m) for m in re.findall(r'line\s+(\d+)', raw_msg, flags=re.IGNORECASE)]
    line_no = min(line_candidates) if line_candidates else 1
    return f"Malformed YAML: {file_path}:{line_no}"

def load_custom_fields(custom_fields_path, reporter: ErrorReporter, allowed_custom_fields_type):
    """
    Load custom fields from 'custom_fields.yml' into a map of field -> (type, array_flag, validation_function).
    """
    custom_fields_map = {}
    try:
        custom_fields_data = rs.ResourceHandler().load_file(custom_fields_path.as_posix())
        seen_by_field = {}
        empty_entry_error_reported = False

        if is_template_file(custom_fields_data):
            reporter.add_warning(
                "Custom Fields",
                custom_fields_path,
                "The 'custom_fields.yml' appears to be a template file. No fields were loaded."
            )
            return {}

        for item in custom_fields_data:
            field_name = (item.get('field') or '').strip()
            ftype = (item.get('type') or '').strip()

            if field_name == "" or ftype == "":
                if not empty_entry_error_reported:
                    reporter.add_error(
                        "Custom Fields",
                        custom_fields_path,
                        "Empty entries detected. Missing 'field' or 'type'."
                    )
                    empty_entry_error_reported = True
                continue

            if field_name in seen_by_field:
                reporter.add_error(
                    "Custom Fields",
                    custom_fields_path,
                    f"Duplicate field '{field_name}'. Field names must be unique."
                )
                continue

            seen_by_field[field_name] = True

            if ftype not in allowed_custom_fields_type:
                reporter.add_error(
                    "Custom Fields",
                    custom_fields_path,
                    f"Invalid type '{ftype}' for field '{field_name}'. "
                    f"Allowed types: {allowed_custom_fields_type}"
                )
                continue

            declared_array_flag = bool(item.get('array', False))
            if ftype == 'nested':
                if declared_array_flag:
                    reporter.add_warning(
                        "Custom Fields", custom_fields_path,
                        f"Field '{field_name}': 'type: nested' implies array; 'array: true' is redundant."
                    )
                array_flag = True
            else:
                array_flag = declared_array_flag

            validation_fn = get_validation_function(ftype)
            custom_fields_map[field_name] = (ftype, array_flag, validation_fn)

        return custom_fields_map

    except Exception as e:

        reporter.add_error(
            "Load Custom Fields",
            str(custom_fields_path),
            _format_yaml_parse_error(str(e), str(custom_fields_path))
        )
        return None


def transform_dict_to_list(d):
    def extract_keys(d, prefix=""):
        result = []
        if isinstance(d, dict):
            for key, value in d.items():
                new_prefix = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict):
                    result.extend(extract_keys(value, new_prefix))
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            result.extend(extract_keys(item, f"{new_prefix}[{i}]"))
                        else:
                            result.append(f"{new_prefix}")
                else:
                    result.append(new_prefix)
        return result

    return extract_keys(d)


def ancestors(field: str):
    """
    Returns hierarchical prefixes of a field.
    E.g.: 'a.b.c.d' -> ['a', 'a.b', 'a.b.c']
    """
    parts = field.split('.')
    acc = []
    out = []
    for p in parts[:-1]:
        acc.append(p)
        out.append('.'.join(acc))
    return out


def verify_schema_types(schema, expected_json_files, custom_fields_map, integration_name, reporter, custom_fields_path):
    """
    Compare the fields in the '_expected.json' files with the schema and custom fields.
    """
    try:
        with open(schema, 'r') as schema_file:
            schema_data = json.load(schema_file)
            schema_fields_info = schema_data.get("fields", {})
            schema_field_names = set(schema_fields_info.keys())
            schema_field_types = {k: v.get("type") for k, v in schema_fields_info.items()}
    except Exception as e:
        reporter.add_error(integration_name, str(schema), f"Error reading the JSON schema file: {e}")
        return

    base_root = Path(schema).resolve().parent.parent

    _CANON_RE = re.compile(r"\[\d+\]")
    def _canon(p: str) -> str:
        return _CANON_RE.sub("", p)

    def _is_under_geopoint(field_path: str) -> bool:
        for anc in ancestors(field_path):
            if schema_field_types.get(anc) == 'geo_point':
                return True
        return False

    def _remove_children(candidates: set, parent_field: str) -> None:
        parent_c = _canon(parent_field)
        for inv in list(candidates):
            inv_c = _canon(inv)
            if inv_c == parent_c or inv_c.startswith(parent_c + '.'):
                candidates.discard(inv)

    def _get_all_values_from_hierarchy(data, field):
        """
        Return a list with all values found at 'field', traversing lists-of-objects implicitly.
        If nothing is found, return None.
        """
        keys = field.split('.')

        def rec(node, i):
            if i == len(keys):
                return [node]
            key = keys[i]
            out = []
            if isinstance(node, dict):
                if key in node:
                    out.extend(rec(node[key], i + 1))
            elif isinstance(node, list):
                for el in node:
                    out.extend(rec(el, i))
            return out

        vals = rec(data, 0)
        return vals if vals else None

    def _validate_array(field, ftype, validate_fn, value, add_err):
        """
        Validate an array-typed custom field.
        Nulls (None) are treated as non-fatal: they raise a warning and are ignored.
        """
        if value is None:
            reporter.add_warning(integration_name, json_file, f"Field '{field}': null array value ignored")
            return True

        if ftype == 'nested' and isinstance(value, dict):
            value = [value]
        if not isinstance(value, list):
            add_err(f"Field '{field}' declared as array, but schema emits a scalar value: {repr(value)}")
            return False

        is_valid = True
        for el in value:
            if el is None:
                reporter.add_warning(integration_name, json_file, f"Field '{field}': null array element ignored")
                continue
            if ftype == 'nested':
                if not isinstance(el, dict):
                    got_t = infer_type_name_for_error(el, ftype)
                    add_err(f"Field '{field}' nested elements must be objects; got '{got_t}' (value={repr(el)})")
                    is_valid = False
                else:
                    if not el:
                        reporter.add_warning(integration_name, json_file, f"Field '{field}': empty object value '{{}}'")
            else:
                if ftype in {'object', 'flattened'} and isinstance(el, dict) and not el:
                    reporter.add_warning(integration_name, json_file, f"Field '{field}': empty object value '{{}}'")

                try:
                    is_valid_element = validate_fn(el)
                except TypeError:
                    is_valid_element = False

                if not is_valid_element:
                    got_t = infer_type_name_for_error(el, ftype)
                    if ftype in {'date', 'date_nanos'}:
                        add_err(
                            f"Field '{field}' declared as '{ftype}' has incompatible scalar value "
                            f"got '{got_t}' (value={repr(el)})"
                        )
                    else:
                        add_err(
                            f"Field '{field}' array element type mismatch: expected '{ftype}', "
                            f"got '{got_t}' (value={repr(el)})"
                        )
                    is_valid = False
        return is_valid

    def _validate_scalar(field, ftype, validate_fn, value, add_err):
        """
        Validate a scalar-typed custom field.
        Null (None) is treated as non-fatal: it raises a warning and is ignored.
        """
        if value is None:
            reporter.add_warning(integration_name, json_file, f"Field '{field}': null value ignored")
            return True

        if isinstance(value, list):
            add_err(f"Field '{field}' declared scalar, but schema emits an array")
            return False

        if ftype == 'nested':
            if not isinstance(value, dict):
                got_t = infer_type_name_for_error(value, ftype)
                add_err(f"Field '{field}' nested must be an object or array of objects; got '{got_t}' (value={repr(value)})")
                return False
            if not value:
                reporter.add_warning(integration_name, json_file, f"Field '{field}': empty object value '{{}}'")
            return True

        if ftype in {'object', 'flattened'} and isinstance(value, dict) and not value:
            reporter.add_warning(integration_name, json_file, f"Field '{field}': empty object value '{{}}'")

        try:
            is_valid_value = validate_fn(value)
        except TypeError:
            is_valid_value = False

        if not is_valid_value:
            got_t = infer_type_name_for_error(value, ftype)
            if ftype in {'date', 'date_nanos'}:
                add_err(
                    f"Field '{field}' declared as '{ftype}' has incompatible scalar value "
                    f"got '{got_t}' (value={repr(value)})"
                )
            else:
                add_err(
                    f"Field '{field}' declared as '{ftype}' has incompatible scalar value "
                    f"(got type '{got_t}', value={repr(value)})"
                )
            return False
        return True

    try:
        custom_rel = Path(custom_fields_path).resolve().relative_to(base_root).as_posix()
    except Exception:
        custom_rel = Path(custom_fields_path).as_posix()

    for json_file in expected_json_files:
        try:
            with open(json_file, 'r') as f:
                expected_data = json.load(f)

                file_unknowns = set()
                custom_errors = set()
                add_err = custom_errors.add

                for expected in expected_data:
                    extracted_fields = transform_dict_to_list(expected)
                    invalid_fields = [
                        field for field in extracted_fields
                        if field not in schema_field_names
                    ]

                    filtered_invalid_fields = set(invalid_fields)

                    for inv in list(filtered_invalid_fields):
                        if _is_under_geopoint(inv):
                            filtered_invalid_fields.discard(inv)

                    for field, (ftype, is_array, validate_function) in custom_fields_map.items():
                        occurrences = _get_all_values_from_hierarchy(expected, field)
                        if not occurrences:
                            continue
                        if is_array:
                            had_json_list_leaf = any(isinstance(v, list) for v in occurrences)

                            if (not had_json_list_leaf) and len(occurrences) == 1 and ftype != 'nested':
                                only = occurrences[0]
                                if only is not None and not isinstance(only, list):
                                    add_err(
                                        f"Field '{field}' declared as array, but JSON emits a scalar value: {repr(only)}"
                                    )

                            agg = []
                            for v in occurrences:
                                if isinstance(v, list):
                                    agg.extend(v)
                                else:
                                    agg.append(v)
                            _ = _validate_array(field, ftype, validate_function, agg, add_err)
                        else:
                            for v in occurrences:
                                _ = _validate_scalar(field, ftype, validate_function, v, add_err)

                        _remove_children(filtered_invalid_fields, field)

                    if filtered_invalid_fields:
                        file_unknowns.update(_canon(f) for f in filtered_invalid_fields)

                if custom_errors:
                    message = "Errors in: " + f"'{custom_rel}'" + "".join(f"\n      - {m}" for m in sorted(custom_errors))
                    reporter.add_error(integration_name, json_file, message)

                if file_unknowns:
                    unknowns = sorted(file_unknowns)
                    message = "Unknown fields in: " + f"'{custom_rel}'" + "".join(f"\n      - {u}" for u in unknowns)
                    reporter.add_error(integration_name, json_file, message)

        except Exception as e:
            reporter.add_error(integration_name, str(json_file), f"Error reading the file: {e}")


def find_expected_json_files(test_folder):
    return list(test_folder.rglob('*_expected.json'))


def _collect_unknown_fields_from_expected(expected_json_files, schema_field_names, schema_field_types, reporter=None, integration_name=None):
    """
    Lightweight pre-scan to decide whether custom fields are required.
    Returns a set of canonical unknown field paths (indices stripped).
    """
    _CANON_RE = re.compile(r"\[\d+\]")

    def _canon(p: str) -> str:
        return _CANON_RE.sub("", p)

    def _is_under_geopoint(field_path: str) -> bool:
        parts = field_path.split('.')
        acc = []
        for p in parts[:-1]:
            acc.append(p)
            anc = '.'.join(acc)
            if schema_field_types.get(anc) == 'geo_point':
                return True
        return False

    unknowns = set()
    for json_file in expected_json_files:
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            if reporter and integration_name:
                reporter.add_error(integration_name, str(json_file), f"Error reading the file: {e}")
            continue

        for expected in data:
            extracted_fields = transform_dict_to_list(expected)
            for field in extracted_fields:
                if field not in schema_field_names and not _is_under_geopoint(field):
                    unknowns.add(_canon(field))

    return unknowns


def verify(schema, integration: Path, reporter):
    try:
        with open(schema, 'r') as schema_file:
            schema_data = json.load(schema_file)
    except Exception as e:
        sys.exit(f"Error reading the JSON schema file: {e}")

    fields_info = schema_data.get("fields", {})
    allowed_custom_fields_type = {field_info.get("type") for field_info in fields_info.values()}
    allowed_custom_fields_type.discard(None)
    allowed_custom_fields_type.update({'date', 'date_nanos'})
    schema_field_names = set(fields_info.keys())
    schema_field_types = {k: v.get("type") for k, v in fields_info.items()}

    if integration.name != 'wazuh-core':
        custom_fields_path = integration / 'test' / 'custom_fields.yml'

        test_folder = integration / 'test'
        if not test_folder.exists() or not test_folder.is_dir():
            reporter.add_error(integration.name, str(test_folder), "Error: No 'test' folder found.")
            return

        expected_json_files = find_expected_json_files(test_folder)
        if not expected_json_files:
            reporter.add_error(integration.name, str(test_folder), "Error: No '_expected.json' files found.")
            return

        # If custom_fields.yml is missing, only skip when no custom fields are required.
        if not custom_fields_path.exists():
            unknowns = _collect_unknown_fields_from_expected(
                expected_json_files, schema_field_names, schema_field_types, reporter, integration.name
            )
            if unknowns:
                missing_rel = (integration / 'test' / 'custom_fields.yml').as_posix()
                msg = "Missing 'custom_fields.yml' but expected JSONs contain fields outside the schema:\n" + \
                      "".join(f"      - {u}\n" for u in sorted(unknowns))
                reporter.add_error(integration.name, missing_rel, msg.rstrip())
                return
            # No unknowns => no custom fields required. It's valid to skip.
            return

        # custom_fields.yml exists (maybe empty/template): proceed with the full validation flow.
        custom_fields = load_custom_fields(custom_fields_path, reporter, allowed_custom_fields_type)
        if custom_fields is None:
            # Fatal parse/load error already reported; abort to avoid noisy "Unknown fields".
            return
        verify_schema_types(schema, expected_json_files, custom_fields, integration.name, reporter, custom_fields_path)


def integration_validator(schema, ruleset_path: Path, integration: str, reporter):
    integration_path = ruleset_path / 'integrations'
    if not integration_path.exists() or not integration_path.is_dir():
        reporter.add_error("Integration Validator", str(integration_path),
                           "Error: 'integrations' directory does not exist.")
        return

    if integration:
        folder = integration_path / integration
        if not folder.exists():
            sys.exit(f"Integration {integration} does not exist.")
        verify(schema, integration_path / integration, reporter)
    else:
        for integration in integration_path.iterdir():
            if integration.is_dir():
                verify(schema, integration, reporter)


def rules_validator(schema, ruleset_path: Path, integration_rule: str, reporter):
    rule_integration_path = ruleset_path / 'integrations'
    if not rule_integration_path.exists() or not rule_integration_path.is_dir():
        reporter.add_error("Integration Validator", str(rule_integration_path),
                           "Error: 'integrations' directory does not exist.")
        return

    if integration_rule:
        folder = rule_integration_path / integration_rule
        if not folder.exists():
            sys.exit(f"Integration {integration_rule} does not exist.")
        verify(schema, rule_integration_path / integration_rule, reporter)
    else:
        for integration in rule_integration_path.iterdir():
            if integration.is_dir():
                verify(schema, integration, reporter)


def run(args):
    ruleset_path = Path(args['ruleset']).resolve()
    integration = args.get('integration')
    integration_rule = args.get('integration_rule')

    if not ruleset_path.is_dir():
        sys.exit(f"Engine ruleset not found: {ruleset_path}")

    schema = ruleset_path / "schemas/engine-schema.json"
    reporter = ErrorReporter("Validation")

    if integration_rule and integration:
        sys.exit("Error: Only one of 'integration' or 'integration_rule' can be specified at a time.")

    try:
        print("Running schema tests.")

        if integration:
            print("Validating integration only.")
            integration_validator(schema, ruleset_path, integration, reporter)

        elif integration_rule:
            print("Validating rules only.")
            rules_validator(schema, ruleset_path, integration_rule, reporter)

        else:
            print("Validating both integration and rules.")
            integration_validator(schema, ruleset_path, integration, reporter)
            rules_validator(schema, ruleset_path, integration_rule, reporter)

        reporter.print_warnings(
            "Non-fatal issues detected (redundant configuration or permissive values)",
            ruleset_path)
        reporter.report_title = "VALIDATION ERRORS:"
        reporter.exit_with_errors(
            "Schema mismatches detected (unknown fields, type errors, or array/scalar cardinality)",
            ruleset_path)

        print("Success execution")
    except Exception as e:
        sys.exit(f"Error running test: {e}")
