from typing import Set, Tuple, Dict, Any, DefaultDict, List
from collections import defaultdict
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


def build_geo_as_enrichment_map_from_flat(
    wcs_flat: Dict[str, Dict[str, Any]],
    exclude_ip_fields: Set[str] | None = None,
) -> Dict[str, Dict[str, str]]:
    exclude_ip_fields = exclude_ip_fields or set()
    result: Dict[str, Dict[str, str]] = {}

    def field_type(meta: Any) -> str:
        if isinstance(meta, dict) and isinstance(meta.get("type"), str):
            return meta["type"].lower()
        return ""

    # Build implicit containers (so "destination.geo.*" implies "destination.geo" exists)
    containers: Set[str] = set()
    for k in wcs_flat.keys():
        parts = k.split(".")
        for i in range(1, len(parts)):
            containers.add(".".join(parts[:i]))

    def container_exists(path: str) -> bool:
        return path in wcs_flat or path in containers

    # 1) Build the mapping
    for ip_field, meta in wcs_flat.items():
        if ip_field in exclude_ip_fields:
            continue
        if field_type(meta) != "ip":
            continue
        if "." not in ip_field:
            continue

        parent = ip_field.rsplit(".", 1)[0]
        entry: Dict[str, str] = {}

        geo_path = f"{parent}.geo"
        if container_exists(geo_path):
            entry["geo_field"] = geo_path

        as_path = f"{parent}.as"
        asn_path = f"{parent}.asn"
        if container_exists(as_path):
            entry["as_field"] = as_path
        elif container_exists(asn_path):
            entry["as_field"] = asn_path

        if entry:
            result[ip_field] = entry

    # 2) Validate: no duplicates (same geo/as target) across different IP fields
    by_target: DefaultDict[Tuple[str | None, str | None], List[str]] = defaultdict(list)

    for ip_field, mapping in result.items():
        geo = mapping.get("geo_field")
        asf = mapping.get("as_field")
        by_target[(geo, asf)].append(ip_field)

    collisions = {t: ips for t, ips in by_target.items() if len(ips) > 1}

    if collisions:
        lines: List[str] = []
        lines.append("Geo/ASN enrichment map validation failed: duplicated targets detected.")

        for (geo, asf), ips in sorted(
            collisions.items(),
            key=lambda x: ((x[0][0] or ""), (x[0][1] or ""))
        ):
            parts = []
            if geo:
                parts.append(f"geo={geo}")
            if asf:
                parts.append(f"as={asf}")
            target_str = " ".join(parts) if parts else "(empty target)"
            lines.append(f"  - {target_str} <- {', '.join(sorted(ips))}")

        raise ValueError("\n".join(lines))

    return result


# ---------------------------------------------------------------------
# New: Enrichment sources generator (connection / url_full / url_domain / hash)
# ---------------------------------------------------------------------

def build_enrichment_sources_config_from_flat(
    wcs_flat: Dict[str, Dict[str, Any]],
    enrichment_cfg: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Generates a config file with source fields used to enrich events per DB type.

    Output format:
      {
        "connection": { "sources": [ {"ip_field": "...", "port_field": "..."} ] },
        "url_full": { "sources": ["url.full", "url.original"] },
        "url_domain": { "sources": ["..."] },
        "hash_md5": { "sources": [...] },
        "hash_sha1": { "sources": [...] },
        "hash_sha256": { "sources": [...] }
      }
    """

    def field_type(meta: Any) -> str:
        if isinstance(meta, dict) and isinstance(meta.get("type"), str):
            return meta["type"].lower()
        return ""

    def field_desc(meta: Any) -> str:
        if isinstance(meta, dict) and isinstance(meta.get("short"), str):
            return meta["short"]
        return ""

    def is_excluded(field: str, exclude_trees: Set[str]) -> bool:
        for t in exclude_trees:
            if field == t or field.startswith(t + "."):
                return True
        return False

    def effective_exclude_trees(type_name: str) -> Set[str]:
        g = enrichment_cfg.get("global", {}) or {}
        types = enrichment_cfg.get("types", {}) or {}
        global_trees = set(g.get("exclude_trees", []) or [])
        type_trees = set((((types.get(type_name, {}) or {}).get("exclude", {}) or {}).get("exclude_trees", []) or []))
        return global_trees | type_trees

    out: Dict[str, Any] = {
        "connection": {"sources": []},
        "url_full": {"sources": []},
        "url_domain": {"sources": []},
    }

    types_cfg = enrichment_cfg.get("types", {}) or {}

    # 1) connection
    conn_cfg = types_cfg.get("connection", {}) or {}
    if conn_cfg.get("enabled", False):
        exclude_trees = effective_exclude_trees("connection")
        include = (conn_cfg.get("include", {}) or {})
        rule = (include.get("sibling_pair_rule", {}) or {})
        ip_names = rule.get("ip_field_names", []) or []
        port_names = rule.get("port_field_names", []) or []

        # group leaves by parent
        by_parent: DefaultDict[str, Dict[str, str]] = defaultdict(dict)
        for f in wcs_flat.keys():
            if is_excluded(f, exclude_trees):
                continue
            if "." not in f:
                continue
            parent, leaf = f.rsplit(".", 1)
            by_parent[parent][leaf] = f

        sources: List[Dict[str, str]] = []
        for parent, leaf_map in sorted(by_parent.items()):
            ip_field = None
            port_field = None

            for ip_leaf in ip_names:
                cand = leaf_map.get(ip_leaf)
                if cand and field_type(wcs_flat.get(cand, {})) == "ip":
                    ip_field = cand
                    break

            for port_leaf in port_names:
                cand = leaf_map.get(port_leaf)
                if cand:
                    port_field = cand
                    break

            if ip_field and port_field:
                sources.append({"ip_field": ip_field, "port_field": port_field})

        out["connection"]["sources"] = sources

    # 2) url_full
    url_full_cfg = types_cfg.get("url_full", {}) or {}
    if url_full_cfg.get("enabled", False):
        exclude_trees = effective_exclude_trees("url_full")
        include = (url_full_cfg.get("include", {}) or {})
        explicit_fields = include.get("explicit_fields", []) or []

        selected: Set[str] = set()
        for f in explicit_fields:
            if f in wcs_flat and not is_excluded(f, exclude_trees):
                selected.add(f)

        out["url_full"]["sources"] = sorted(selected)

    # 3) url_domain
    url_domain_cfg = types_cfg.get("url_domain", {}) or {}
    if url_domain_cfg.get("enabled", False):
        exclude_trees = effective_exclude_trees("url_domain")
        include = (url_domain_cfg.get("include", {}) or {})

        by_contains = include.get("by_field_contains", []) or []
        explicit_fields = include.get("explicit_fields", []) or []

        # OJO: ahora esto se usa como EXCLUSION por description
        desc_cfg = include.get("by_description_exact", {}) or {}
        desc_enabled = bool(desc_cfg.get("enabled", False))
        desc_values = set(desc_cfg.get("values", []) or [])

        selected: Set[str] = set()

        # explicit
        for f in explicit_fields:
            if f in wcs_flat and not is_excluded(f, exclude_trees):
                selected.add(f)

        # by contains on field name
        for f in wcs_flat.keys():
            if is_excluded(f, exclude_trees):
                continue
            if any(tok in f for tok in by_contains):
                selected.add(f)

        # EXCLUDE by description exact
        if desc_enabled and desc_values:
            to_remove: Set[str] = set()
            for f in selected:
                meta = wcs_flat.get(f)
                if meta is None:
                    continue
                if field_desc(meta) in desc_values:
                    to_remove.add(f)
            selected -= to_remove

        out["url_domain"]["sources"] = sorted(selected)

    # 4) hash by algorithm (flat structure: hash_md5, hash_sha1, etc.)
    hash_cfg = types_cfg.get("hash", {}) or {}
    if hash_cfg.get("enabled", False):
        algorithms = (hash_cfg.get("algorithms", {}) or {})
        for algorithm_name, algorithm_cfg in algorithms.items():
            algorithm_cfg = algorithm_cfg or {}
            if not algorithm_cfg.get("enabled", False):
                continue

            # global + (hash exclude) + (algo exclude)
            g_trees = set((enrichment_cfg.get("global", {}) or {}).get("exclude_trees", []) or [])
            hash_trees = set(((hash_cfg.get("exclude", {}) or {}).get("exclude_trees", []) or []))
            algo_trees = set((((algorithm_cfg.get("exclude", {}) or {}).get("exclude_trees", []) or [])))
            exclude_trees = g_trees | hash_trees | algo_trees

            include = (algorithm_cfg.get("include", {}) or {})
            tokens = include.get("by_field_contains", []) or []

            selected: Set[str] = set()
            for f in wcs_flat.keys():
                if is_excluded(f, exclude_trees):
                    continue
                if any(tok in f for tok in tokens):
                    selected.add(f)

            # Use flat key format: hash_md5, hash_sha1, etc.
            out[f"hash_{algorithm_name}"] = {"sources": sorted(selected)}

    return out


def generate(wcs_path: str, resource_handler: rs.ResourceHandler, exclude_geo: Set[str], enrichment_cfg: dict) -> Tuple[dict, dict, dict, dict, dict, dict]:
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

        print('Generating geo/as enrichment map...')
        geo_enrichment_map = build_geo_as_enrichment_map_from_flat(wcs_flat, exclude_geo)
        print('Success.')

        # New: generate enrichment sources config
        print('Generating enrichment sources config...')
        enrichment_sources_config = build_enrichment_sources_config_from_flat(wcs_flat, enrichment_cfg)
        print('Success.')

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

        return (
            decoder_fields_schema,
            mappings_properties,
            logpar_template,
            engine_schema,
            geo_enrichment_map,
            enrichment_sources_config,
        )

    finally:
        # Clean up temporary file if it was created
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.unlink(temp_file_path)
                print(f'Cleaned up temporary file: {temp_file_path}')
            except Exception as e:
                print(f'Warning: Could not delete temporary file {temp_file_path}: {e}')
