import socket
import struct
import time

import yaml

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

    with open('/configuration_files/agent_info_output', 'a+') as f:
        for agent in agent_info:
            # Add last_keepalive with epoch time
            try:
                agent['agent']['last_keepalive'] = int(time.time()) - \
                                                            3600*24*int(agent['extra_params']['days_from_last_connection'])
            except KeyError:
                pass

            # Update fields of agent table
            try:
                query = "UPDATE agent SET " + \
                        ", ".join(['{0} = {1}'.format(key, value) if isinstance(value, int)
                                   else '{0} = "{1}"'.format(key, value)
                                   for key, value in agent['agent'].items()]) + \
                        f" WHERE id = {agent['extra_params']['agent_id']}"
                # Send query to wdb
                f.write(str(send_msg("global sql " + query)))
            except KeyError:
                pass

            # Insert fields of labels table
            try:
                for key, value in agent['labels'].items():
                    query = f"INSERT INTO labels ('id', 'key', 'value') VALUES " \
                            f"({agent['extra_params']['agent_id']}, '{key}', '{value}')"
                    # Send query to wdb
                    f.write(str(send_msg("global sql " + query)))
            except KeyError:
                pass


if __name__ == "__main__":
    create_and_send_query('/configuration_files/master_only/agent_info.yaml')
