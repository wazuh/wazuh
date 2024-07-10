#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
from pathlib import Path
from typing import Tuple, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
WAZUH_DIR = Path(SCRIPT_DIR).resolve().parent.parent.parent.parent


def parse_arguments() -> Tuple[str, str]:
    parser = argparse.ArgumentParser(description='Run Behave tests for Wazuh.')
    parser.add_argument('-e', '--environment', help='Environment directory')
    parser.add_argument(
        '-f', '--feature', help='Feature file to run (default: all features)')

    args = parser.parse_args()
    return args.environment, args.feature


def get_config_file(env_dir: Path) -> Path:
    conf_path = env_dir / "engine" / "general.conf"

    if not conf_path.exists():
        print(f"Error: Configuration file {conf_path} not found.")
        sys.exit(1)

    if not conf_path.is_file():
        print(f"Error: {conf_path} is not a file.")
        sys.exit(1)

    return conf_path


def run_behave_tests(it_path: Path, feature_path: Optional[Path]) -> int:
    result_code = 0

    if feature_path:
        print(f"\n\n=====> Start Behave {feature_path}")
        result = subprocess.run(
            ['behave', feature_path.as_posix(), '--tags', '~exclude', '--format', 'progress2'])
        print(f"<===== End")
        if result.returncode != 0:
            result_code = 1

    else:
        failed_tests = []
        for test_dir in it_path.iterdir():
            if test_dir.is_dir() and (test_dir / "features").is_dir() and (test_dir / "steps").is_dir():
                print(f"\n\n=====> Start Behave {test_dir}")
                result = subprocess.run(
                    ['behave', test_dir, '--tags', '~exclude', '--format', 'progress2'])
                print(f"<===== End")
                if result.returncode != 0:
                    result_code = 1
                    failed_tests.append(test_dir.name)

        if len(failed_tests) > 0:
            print(f"\n\n=====> Failed tests:")
            for test in failed_tests:
                print(f"    {test}")

    return result_code


def main():
    env_dir, specific_feature = parse_arguments()

    # Get paths
    engine_path = WAZUH_DIR / "src" / "engine"
    env_path = Path(env_dir).resolve()
    conf_path = get_config_file(env_path)
    it_path = engine_path / "test" / "integration_tests"
    feature_path = Path(specific_feature).resolve() if specific_feature else None

    if feature_path and not feature_path.exists():
        print(f"Error: Feature path {feature_path} not found.")
        sys.exit(1)

    # Set environment variables so the tests can use the paths
    os.environ['ENGINE_DIR'] = engine_path.as_posix()
    os.environ['ENV_DIR'] = env_path.as_posix()
    os.environ['BINARY_DIR'] = (engine_path / 'build' / 'main').as_posix()
    os.environ['CONF_FILE'] = conf_path.as_posix()

    print(f'Testing environment: {env_path}')
    print(f'Using configuration file: {conf_path}')
    print(f'Running tests from: {it_path}')
    print(f'Engine path: {engine_path}')
    print(f'Wazuh path: {WAZUH_DIR}')

    exit_code = run_behave_tests(it_path, feature_path)
    print(f"Exit code {exit_code}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
