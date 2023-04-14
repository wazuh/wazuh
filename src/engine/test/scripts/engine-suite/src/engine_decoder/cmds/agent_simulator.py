# from pathlib import Path
import shared.resource_handler as rs
import json

WRITE_MESSAGE_GO_PATH = '/var/ossec/queue/sockets/queue'
WRITE_MESSAGE_GO_PATH_ARGUMENTS = ''

SOURCES_LIST_PATH = '/home/vagrant/workspace/wazuh/src/engine/test/scripts/engine-suite/sources-list.yml'


def run(args, resource_handler: rs.ResourceHandler):
    # TODO: pending loop for several sources and several events

    agent = args['agent']
    sources = args['source']
    modules = args['module']
    file_path = args['file']
    # engine_socket = args['engine-socket']
    # eps = args['eps']
    # timeout = args['timeout']

    modules_queue = {
        'windowsEventChannel' : 102,
        'windowsEventLog' : 49,
        'syscollector' : 100
        }

    # According to source gets queue
    protocol_queue = modules_queue[modules]

    # fill fixed fields for agent
    agent_name = 'agent_name'
    agent_IP = '192.168.150.120'
    origin = modules
    protocol_location = '[' + agent + '] ('+ agent_name +') ' + agent_IP + '->'+origin

    #look into yaml file_path from [module][source]
    source_list_content = resource_handler.load_file(file_path, rs.Format.YML)
    if not source_list_content:
        print('File must not be empty.')
        exit(1)

    if sources in source_list_content:
        for sources_block in source_list_content[sources]:
            if modules in sources_block:
                for entry in sources_block[modules]:
                    base_event = entry

    final_event = chr(protocol_queue) + ":" + protocol_location + base_event
    print(final_event)


def configure(subparsers):
    # agent_simulator = subparsers.add_parser(
    #     'send_event', help='Creates and send a sample event based on configurations')

    # agent_simulator.add_argument(
    #     '-t', '--timeout', help=f'After which the communication will stop', type=str, dest='timeout')

    # agent_simulator.add_argument(
    #     '-E', '--eps', help=f'Repeat all possible events to send undefinetly respecting the EPS', type=str, dest='eps')

    # agent_simulator.add_argument(
    #     '-e', '--engine-socket', help=f'Where the engine is listening to events', type=str, dest='engine-socket')

    agent_simulator = subparsers.add_parser(
        'create_event', help='Creates a sample event based on configurations')

    agent_simulator.add_argument(
        '-a', '--agent-id', help=f'Agent ID for filling events', type=str, dest='agent', default='001')

    agent_simulator.add_argument(
        '-s', '--source', help=f'Source or list of sources (separated by comma) of events', type=str, dest='source')

    agent_simulator.add_argument(
        '-m', '--module', help=f'module or list of modules (separated by comma) of events', type=str, dest='module')

    agent_simulator.add_argument('-f', '--file', help=f'File where to look for sample events templates', type=str, dest='file',
                                 default=SOURCES_LIST_PATH)  # TODO CHANGE

    agent_simulator.set_defaults(func=run)
