from pathlib import Path
from health_test.metadata_validate import run as metadata_validate_run
from health_test.schema_validate import run as schema_validate_run
from health_test.mandatory_mapping_validate import run as mandatory_mapping_validate_run
from health_test.event_processing import run as event_processing_run
from health_test.load_decoders import run as load_decoders_run
from health_test.load_rules import run as load_rules_run
from health_test.assets_validate import run as assets_validate_run
from health_test.validate_successful_assets import run as validate_successful_assets_run
from health_test.validate_non_modifiables_fields import run as validate_non_modifiables_fields_run
from health_test.validate_custom_field_documentation import run as validate_custom_field_documentation_run
from health_test.coverage_validate import run as coverage_validate_run
from health_test.core import run as test_run
from health_test.validate_custom_field_indexing import run as validate_custom_field_indexing_run
from health_test.validate_event_indexing import run as validate_event_indexing_run
from health_test.initial_state import run as init_run

STATIC_TESTS = [
  (metadata_validate_run, {"-r": ""}),
  (schema_validate_run, {"-r": ""}),
  (mandatory_mapping_validate_run, {"-r": ""}),
  (event_processing_run, {"-r": ""}),
  (validate_non_modifiables_fields_run, {"-r": ""}),
  (validate_custom_field_documentation_run, {"-r": ""})
]

DYNAMIC_TESTS = [
  (init_run, {"-t": ""}),
  (assets_validate_run, {}),
  (load_decoders_run, {}),
  (validate_successful_assets_run,  {"target": "decoder", "skip": "wazuh-core"}),
  (validate_event_indexing_run , {"target": "decoder", "skip": "wazuh-core"}),
  (validate_custom_field_indexing_run , {"target": "decoder"}),
  (test_run, {"target": "decoder", "skip": "wazuh-core"}),
  (coverage_validate_run, {"target": "decoder", "skip": "wazuh-core", "output_file": "/tmp/decoder_coverage_report.txt"}),
  (load_rules_run, {}),
  (validate_successful_assets_run, {"target": "rule", "skip": "wazuh-core"}),
  (validate_event_indexing_run, {"target": "rule", "skip": "wazuh-core"}),
  (validate_custom_field_indexing_run, {"target": "rule"}),
  (test_run, {"target": "rule", "skip": "wazuh-core"})
]

def update_log_level(environment:str):
    conf = Path(environment) / "config.env"
    with conf.open("r") as file:
        lines = file.readlines()

    with conf.open("w") as file:
        for line in lines:
            if line.startswith("WAZUH_LOG_LEVEL="):
                file.write("WAZUH_LOG_LEVEL=critical\n")
            elif line.startswith("WAZUH_SERVER_API_TIMEOUT="):
                file.write("WAZUH_SERVER_API_TIMEOUT=1000000\n")
            else:
                file.write(line)

def run(args):
    environment = args["environment"]
    ruleset = args["ruleset"]
    health_test_path = args['test_dir']

    for test, kwargs in STATIC_TESTS:
        test_args = kwargs.copy()

        if "-r" in test_args:
            test_args["ruleset"] = ruleset

        test(test_args)

    first = True
    for test, kwargs in DYNAMIC_TESTS:
        test_args = kwargs.copy()

        if "-t" in test_args:
            test_args["test_dir"] = health_test_path

        test_args["ruleset"] = ruleset
        test_args["environment"] = environment

        test(test_args)

        if first:
            update_log_level(environment)
            first = False
