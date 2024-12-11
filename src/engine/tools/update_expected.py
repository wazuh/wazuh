#!/usr/bin/env python3

from pathlib import Path
from argparse import ArgumentParser
from typing import Callable
import subprocess
import time
from json import dumps, loads


def visitor(path: Path, pattern: str, visit: Callable):
    for file in path.rglob(pattern):
        if file.is_file():
            visit(file)
        elif file.is_dir():
            visitor(file, pattern, visit)


def get_executor(test_command: str, output: Path):
    def executor(file):
        # Set up command
        output_file = output / file.with_name(
            file.stem.replace('input', 'expected') + '.json').name
        command = f'cat {file} | {test_command}'

        try:
            # Execute command
            print(f'Running: {command}')
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, check=True)

            # For each line in the output, parse it as JSON and remove the TestSessionID
            expecteds = []
            for line in result.stdout.splitlines():
                parsed = loads(line)
                parsed.pop('TestSessionID', None)
                expecteds.append(parsed)

            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(dumps(expecteds, indent=2))

            # Notify the user
            print(f'{file.name} -> {output_file.name}')
        except Exception as e:
            print(f'{file.name} -> {e}')

    return executor


if __name__ == '__main__':
    try:
        arg_parser = ArgumentParser(description='Update expected results')
        arg_parser.add_argument(
            'environment', help='Environment folder where the test configuration is stored.', type=Path)
        arg_parser.add_argument(
            'path', type=Path, help='Path to the directory with input files')
        arg_parser.add_argument('pattern', help='Pattern for the input files')
        arg_parser.add_argument(
            'test_integration', help='engine-test integration if any')
        arg_parser.add_argument(
            'test_integration_conf_file', help='engine-test integration configuration file')
        arg_parser.add_argument('-o', '--output', type=Path,
                                help='Path to the output file, default: /tmp/update_expected/', default='/tmp/update_expected/')
        arg_parser.add_argument(
            '-b', '--binary', help='Specify the path to the engine binary', default='wazuh-engine')
        args = arg_parser.parse_args()

        path = Path(args.path).resolve()
        pattern = args.pattern
        environment = Path(args.environment).resolve()
        test_integration = args.test_integration
        api_sock = environment / 'queue/sockets/engine-api'
        test_command = f'engine-test -c {args.test_integration_conf_file} run {test_integration} --api-socket {api_sock} -j'
        output = args.output
        binary = args.binary
        config_path = environment / 'engine/general.conf'

        # Start the engine
        engine_command = [binary, '--config',
                          str(config_path), 'server', 'start']
        print(f'Starting engine with command: {" ".join(engine_command)}')
        engine = subprocess.Popen(
            engine_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)
        # Check if the engine is running
        if engine.poll() is not None:
            print('Engine failed to start')
            exit(1)

        # Iterate over files, visiting subfolders recursively
        visitor(path, pattern, get_executor(test_command, output))

        engine.terminate()
        engine.wait(5)

        # Notify the user
        print(f'Updated expected results in {output}')
    except KeyboardInterrupt:
        print('Interrupted by the user')
    except Exception as e:
        print(f'Unexpected error: {e}')
