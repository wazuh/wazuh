import argparse
import sys

from engine_test.conf.integration import Formats, IntegrationConf, SubTempleType
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
        raise argparse.ArgumentTypeError(f"{value} is an invalid positive int value")
    return ivalue


def check_args(args):
    # Windows ignores module are automatically set to windows-eventchannel
    if args['format'] == Formats.WINDOWS_EVENTCHANNEL.value:
        if args['module'] != None:
            print(f"Argument -m/--module is ignored for format {args['format']}, setting to windows-eventchannel")
            args['module'] = 'windows-eventchannel'

        # TODO: Move to constant in shared module
        args['module'] = 'windows-eventchannel'

    # If multi-line format, lines are required
    if args['format'] == Formats.MULTI_LINE.value:
        if args['lines'] == None:
            raise argparse.ArgumentTypeError(f"Argument -l/--lines is required for multi-line format")

    # Module and provider are required for all formats
    if args['module'] == None:
        raise argparse.ArgumentTypeError(f"Argument -m/--module is required")
    if args['provider'] == None:
        raise argparse.ArgumentTypeError(f"Argument -p/--provider is required")


def run(args):

    try:
        # Check the args
        args['post_parse'](args)


        # Create integration configuration
        iconf = IntegrationConf(args['integration_name'], args['format'], args['module'],
                                args['provider'], args['event_created'], args['lines'])

        # If provider is not `file` then set the log.file.path
        if args['provider'] == "file":
            iconf.get_template().add_field(SubTempleType.EVENT, "log.file.path", args['log_file_path'])
        else:
            iconf.get_template().remove_field(SubTempleType.EVENT, "log.file.path")

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
    parser.add_argument('-f', '--format', help=f'Format in which events should be handled by engine-test.',
                        choices=Formats.get_formats(), dest='format', required=True)
    parser.add_argument(
        '-m', '--module', help='Name of the module this data is coming from (i.g. apache-error, apache-access, eventchannel, journald, macos-uls)', dest='module')
    parser.add_argument(
        '-p', '--provider', help='Name of the provider, source of data (i.g. file, channel name of eventchannel, unit name of journald, program-name of macos-uls, etc)', dest='provider')
    parser.add_argument(
        '-l', '--lines', help='Fixed number of lines for each event. Only for multi-line format.', dest='lines', type=check_positive)
    parser.add_argument('--log-file-path', help='Path to the log file. Only for file provider.',
                        dest='log_file_path', type=str, default="/var/log/test.log")
    parser.add_argument('--force-event-created', help='Force the event.created date to a specific date. Format: YYYY-MM-DDTHH:MM:SSZ',
                        dest='event_created', type=str, default="auto")

    parser.set_defaults(func=run, post_parse=check_args)
