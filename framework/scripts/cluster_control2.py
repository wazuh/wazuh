#!/usr/bin/env python

from os.path import dirname
from sys import argv, exit, path

# Import framework
try:
    # Search path
    path.append(dirname(argv[0]) + '/../framework')

    # Import and Initialize
    from wazuh import Wazuh
    myWazuh = Wazuh(get_init=True)

    from wazuh.cluster.communication import send_to_internal_socket
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()
#
# Main
#
if __name__ == '__main__':
    node_type = argv[1]

    try:
        message = argv[2]
    except:
        message = "echo test"

    try:
        size = int(argv[3])
    except:
        size = 5

    try:
        send_to_internal_socket(socket_name="c-internal", message=message)
    except KeyboardInterrupt:
        pass
