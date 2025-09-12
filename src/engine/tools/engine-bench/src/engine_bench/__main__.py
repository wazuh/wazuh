import os
import subprocess
import sys
from pathlib import Path
from importlib.resources import files

import click

from engine_handler.handler import EngineHandler


@click.command(context_settings=dict(help_option_names=['-h', '--help']))
@click.option('--environment', '-e', required=True, type=click.Path(exists=True), help='Path to the environment directory.')
@click.option('--output', '-o', required=True, type=click.Path(exists=False), help='Path to the output directory for the benchmark results.')
def main(environment, output):
    """
    Benchmark the Wazuh engine executable using perf.
    """
    # Check if perf is available
    if not is_perf_available():
        click.secho(
            "Error: 'perf' is not available on this system. Please install it to proceed.", fg="red", bold=True)
        sys.exit(1)

    # Check if we have sudo privileges
    if os.geteuid() != 0:
        click.secho(
            "Error: This script requires sudo privileges. Please run it with sudo.", fg="red", bold=True)
        sys.exit(1)

    # Check if the output directory exists (if not, create it)
    output = Path(output)
    if not output.exists():
        click.secho(f"Output directory {output} does not exist. Creating it...", fg="yellow")
        # Create only if the parent directory exists
        if not output.parent.exists():
            click.secho(f"Parent directory {output.parent} does not exist.", fg="red", bold=True)
            sys.exit(1)
        output.mkdir(parents=True, exist_ok=True)

    engine_conf = Path(environment) / 'config.env'
    engine_bin = Path(environment) / 'wazuh-engine'
    engine_log = Path(environment) / 'logs' / 'engine.log'
    engine_log.parent.mkdir(parents=True, exist_ok=True)
    perf_report = output / 'perf.data'

    # Run perf on the engine executable
    try:
        click.echo("Starting Engine")
        engine_handler = EngineHandler(engine_bin.as_posix(), engine_conf.as_posix())
        engine_handler.start(engine_log.as_posix())
        click.echo(f"Engine started pid: {engine_handler.get_pid()}")

        engine_pid = engine_handler.get_pid()

        command = f"perf record -g -p {engine_pid} -o {perf_report.as_posix()} "
        click.echo(f"Running: {command}")
        result = subprocess.Popen(command, shell=True)

        # Sleep for a while to allow perf to collect data
        click.echo("Sleeping for 10 seconds to allow data collection...")
        subprocess.run(["sleep", "10"])

        # Stop the engine
        engine_handler.stop()
        click.echo("Engine stopped")

        result.wait()

        click.echo(f"Output written to {output}/perf.data")

        click.echo("Generating flamegraph")
        stack_collapse_script = files('engine_bench.scripts').joinpath('stackcollapse-perf.pl')
        flamegraph_script = files('engine_bench.scripts').joinpath('flamegraph.pl')
        command = f"perf script -i {perf_report.as_posix()} > {output}/perf.script"

        subprocess.run(command, shell=True, check=True)
        subprocess.run(
            f"perl {stack_collapse_script} {output}/perf.script > {output}/perf.folded", shell=True, check=True)
        subprocess.run(
            f"perl {flamegraph_script} {output}/perf.folded > {output}/flamegraph.svg", shell=True, check=True)
        click.echo(f"Flamegraph generated at {output}/flamegraph.svg")

    except subprocess.CalledProcessError as e:
        click.secho(f"Error while running perf: {e}", fg="red", bold=True)
        sys.exit(1)


def is_perf_available():
    """
    Check if 'perf' is available on the system.
    """
    try:
        subprocess.run(["perf", "--version"], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return True
    except FileNotFoundError:
        return False
    except subprocess.CalledProcessError:
        return False


if __name__ == "__main__":
    main()
