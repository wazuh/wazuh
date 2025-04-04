from pathlib import Path

from shared.default_settings import Constants, CONFIG_ENV_KEYS

from health_test import (
    metadata_validate,
    schema_validate,
    mandatory_mapping_validate,
    event_processing,
    load_decoders,
    load_rules,
    assets_validate,
    validate_successful_assets,
    validate_non_modifiables_fields,
    validate_custom_field_documentation,
    coverage_validate,
    core,
    validate_custom_field_indexing,
    validate_event_indexing,
    initial_state,
)

CRITICAL_LOG_LEVEL = "critical"
SKIP_INTEGRATION = "wazuh-core"

STATIC_TESTS = [
    (metadata_validate.run, {"-r": ""}),
    (schema_validate.run, {"-r": ""}),
    (mandatory_mapping_validate.run, {"-r": ""}),
    (event_processing.run, {"-r": ""}),
    (validate_non_modifiables_fields.run, {"-r": ""}),
    (validate_custom_field_documentation.run, {"-r": ""}),
]

DYNAMIC_TESTS = [
    (initial_state.run, {"-t": ""}),
    (assets_validate.run, {}),
    (load_decoders.run, {}),
    (validate_successful_assets.run, {"target": "decoder", "skip": SKIP_INTEGRATION}),
    (validate_event_indexing.run, {"target": "decoder", "skip": SKIP_INTEGRATION}),
    (validate_custom_field_indexing.run, {"target": "decoder", "skip": SKIP_INTEGRATION}),
    (core.run, {"target": "decoder", "skip": SKIP_INTEGRATION}),
    (coverage_validate.run, {"target": "decoder", "skip": SKIP_INTEGRATION, "output_file": "/tmp/decoder_coverage_report.txt"}),
    (load_rules.run, {}),
    (validate_successful_assets.run, {"target": "rule", "skip": SKIP_INTEGRATION}),
    (validate_event_indexing.run, {"target": "rule", "skip": SKIP_INTEGRATION}),
    (validate_custom_field_indexing.run, {"target": "rule", "skip": SKIP_INTEGRATION}),
    (core.run, {"target": "rule", "skip": SKIP_INTEGRATION}),
]

def update_log_level(environment: str):
    """
    Updates the log level and API timeout in the 'config.env' file
    located inside the specified environment directory.

    Parameters:
        environment (str): Path to the environment directory containing the config file.
    """
    conf = Path(environment) / "config.env"
    with conf.open("r") as file:
        lines = file.readlines()

    with conf.open("w") as file:
        for line in lines:
            if line.startswith(CONFIG_ENV_KEYS.LOG_LEVEL.value):
                file.write(f"{CONFIG_ENV_KEYS.LOG_LEVEL.value}={CRITICAL_LOG_LEVEL}\n")
            elif line.startswith(CONFIG_ENV_KEYS.API_TIMEOUT.value):
                file.write(f"{CONFIG_ENV_KEYS.API_TIMEOUT.value}={Constants.DEFAULT_API_TIMEOUT}\n")
            else:
                file.write(line)

def prepare_arguments(base_args: dict, extra_args: dict) -> dict:
    """
    Combines base arguments with additional arguments for a test function,
    resolving special placeholders like '-r' (ruleset) and '-t' (test_dir).

    Parameters:
        base_args (dict): Dictionary containing shared context arguments.
        extra_args (dict): Specific arguments for the test being run.

    Returns:
        dict: Final dictionary of arguments to be passed to the test function.
    """
    args = extra_args.copy()
    args.update(base_args)
    if "-r" in args:
        args["ruleset"] = base_args["ruleset"]
        del args["-r"]
    if "-t" in args:
        args["test_dir"] = base_args["test_dir"]
        del args["-t"]
    return args

def get_all_tests():
    """
    Generator that yields all test functions and their corresponding arguments,
    combining static and dynamic test lists.

    Yields:
        tuple: (function, argument dictionary) for each test to be executed.
    """
    for test, args in STATIC_TESTS + DYNAMIC_TESTS:
        yield test, args

def run(args):
    """
    Executes all health test functions in order. Static tests are run first,
    followed by dynamic tests. The log level is updated right after the first
    dynamic test is executed.

    Parameters:
        args (dict): Dictionary containing 'environment', 'ruleset', and 'test_dir'.
    """
    base_args = {
        "environment": args["environment"],
        "ruleset": args["ruleset"],
        "test_dir": args["test_dir"]
    }

    update_done = False
    for idx, (test_func, extra_args) in enumerate(get_all_tests()):
        test_args = prepare_arguments(base_args, extra_args)
        test_func(test_args)

        if not update_done and idx == len(STATIC_TESTS):
            update_log_level(base_args["environment"])
            update_done = True
