import sys
import os
import subprocess
from pathlib import Path
from typing import Optional


def run_behave_tests(test_path: Path, feature: Optional[str]) -> int:
    result_code = 0
    if feature:
        feature_path = Path(feature)
        print(f"\n\n=====> Start Behave {feature_path}")
        if not feature_path.is_file():
            print(f"Error: Feature file {feature_path} not found.")
            sys.exit(1)

        result = subprocess.run(
            ['behave', feature_path.as_posix(), '--tags', '~exclude', '--format', 'progress2'])
        print(f"<===== End")
        if result.returncode != 0:
            result_code = 1
    else:
        failed_tests = []
        for test_dir in test_path.iterdir():
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


def it(env_path: Path, test_path: Path, feature: Optional[str]):
    # Start the engine
    print("Validating environment...")
    conf_path = (env_path / "config.env").resolve()
    if not conf_path.exists():
        print(f"Error: Configuration file {conf_path} not found.")
        sys.exit(1)

    bin_path = (env_path / "wazuh-engine").resolve()
    if not bin_path.exists():
        print(f"Error: Engine binary {bin_path} not found.")
        sys.exit(1)
    print("Environment validated.")

    print("Setting up environment variables...")
    os.environ['ENV_DIR'] = env_path.as_posix()
    os.environ['BINARY_DIR'] = bin_path.as_posix()
    os.environ['CONF_FILE'] = conf_path.as_posix()
    print("Environment variables set.")

    print(f'Testing environment: {env_path}')
    print(f'Running tests from: {test_path}')

    exit_code = run_behave_tests(test_path, feature)
    print(f"Exit code {exit_code}")

    sys.exit(exit_code)


def run(args):
    env_path = Path(args['environment']).resolve()
    feature = args['feature']
    test_path = Path(args['test_dir']).resolve()

    it(env_path, test_path, feature)
