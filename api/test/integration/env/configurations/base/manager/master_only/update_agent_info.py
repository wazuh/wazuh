import socket
import struct
import yaml
import json
import time

ADDR = '/var/ossec/queue/db/wdb'
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(ADDR)


def send_msg(msg):
    '''Send message to wazuh-db socket

    Parameters
    ----------
    msg : str
        Message to be formatted and sent
    '''
    msg = struct.pack('<I', len(msg)) + msg.encode()
    # Send msg
    sock.send(msg)
    # Receive response
    data = sock.recv(4)
    data_size = struct.unpack('<I', data[0:4])[0]
    data = sock.recv(data_size).decode(encoding='utf-8', errors='ignore').split(" ", 1)

    return data


def create_and_send_query(agent_info_file):
    with open(agent_info_file) as f:
        agent_info = yaml.safe_load(f)

    with open('/configuration_files/output_agent_info', 'w+') as f:
        for agent in agent_info:
            # Add last_keepalive key-value with epoch time
            try:
                agent['new_agent_info']['last_keepalive'] = int(time.time()) - \
                                                            3600*24*int(agent['extra_params']['last_connection_in_days'])
            except KeyError:
                pass

            f.write(f'GLOBAL.DB before updating agent-info: \n ' +
                    f'{json.dumps(json.loads(send_msg("global sql select * from agent")[1]), indent=4, sort_keys=True)}')

            # Prepare query with all the requested fields
            query = "UPDATE agent SET " + \
                    ", ".join(['{0} = {1}'.format(key, value)
                               if isinstance(value, int) else '{0} = "{1}"'.format(key, value)
                               for key, value in agent['new_agent_info'].items()]) + \
                    f" WHERE id = {agent['extra_params']['agent_id']}"

            # Send update query
            f.write(str(send_msg("global sql " + query)))
            f.write(f'GLOBAL.DB after updating agent-info: \n ' +
                    f'{json.dumps(json.loads(send_msg("global sql select * from agent")[1]), indent=4, sort_keys=True)}')


if __name__ == "__main__":
    create_and_send_query('/configuration_files/agent_info.yaml')
