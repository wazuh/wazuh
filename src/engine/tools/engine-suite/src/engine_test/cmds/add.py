import argparse
import sys

from engine_test.conf.integration import CollectModes, IntegrationConf
from engine_test.conf.store import ConfigDatabase


def check_positive(value):
    '''
    Check if the value is a positive integer. If not, raise an exception.
    '''
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value} is not a valid integer")
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(
            f"{value} is an invalid positive int value")
    return ivalue


def check_args(args):
    # If multi-line collect mode, lines are required
    if args['collect_mode'] == CollectModes.MULTI_LINE.value:
        if args['lines'] == None:
            raise argparse.ArgumentTypeError(
                f"Argument -l/--lines is required for multi-line collect mode")

    # queue and location must be both set or both unset
    queue_set = args.get('queue') is not None
    loc_set = args.get('location') is not None
    if queue_set ^ loc_set:
        raise argparse.ArgumentTypeError(
            "Arguments -q/--queue and -o/--location must both be set or both be omitted.")

def run(args):
    try:
        # Check the args
        args['post_parse'](args)

        # Create integration configuration
        iconf = IntegrationConf(args['integration_name'], args['collect_mode'], args.get('queue', ''),
                                args.get('location', ''), args['lines'])

        # Get the configuration database
        db = ConfigDatabase(args['config_file'], create_if_not_exist=True)
        # Saving integration
        db.add_integration(iconf)

    except Exception as ex:
        sys.exit(f"Error adding integration: {ex}")


def configure(subparsers):

    parser = subparsers.add_parser("add", help='Add integration')

    parser.add_argument('-i', '--integration-name', type=str, help=f'Integration to test name',
                        dest='integration_name', required=True)
    parser.add_argument('-c', '--collect-mode', help=f'Collect mode in which events should be handled by engine-test.',
                        choices=CollectModes.get_collect_modes(), dest='collect_mode', required=True)
    parser.add_argument(
        '-q', '--queue', help='Queue number representing the queue byte in the protocol', dest='queue')
    parser.add_argument(
        '-o', '--location', help='Name of the collector, source of data (i.g. file, windows-eventlog, journald, macos-uls)', dest='location')
    parser.add_argument(
        '-l', '--lines', help='Fixed number of lines for each event. Only for multi-line collect mode.', dest='lines', type=check_positive)

    parser.set_defaults(func=run, post_parse=check_args)
