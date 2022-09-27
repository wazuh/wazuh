import socket
import struct
import time

import yaml

output_file = '/tmp_volume/configuration_files/agent_info_output'
ADDR = '/var/ossec/queue/db/wdb'
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(ADDR)


def send_msg(msg):
    """Send message to wazuh-db socket

    Parameters
    ----------
    msg : str
        Message to be formatted and sent
    """
    encoded_msg = msg.encode(encoding='utf-8')
    packed_msg = struct.pack('<I', len(encoded_msg)) + encoded_msg
    # Send msg
    sock.send(packed_msg)
    # Receive response
    data = sock.recv(4)
    data_size = struct.unpack('<I', data[0:4])[0]
    data = sock.recv(data_size).decode(encoding='utf-8', errors='ignore').split(" ", 1)

    return data


def create_and_send_query(agent_info_file):
    with open(agent_info_file) as f:
        agent_info = yaml.safe_load(f)

    with open(output_file, 'a+') as f:
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
                f.write(str(send_msg("global sql " + query)) + '\n')
            except KeyError:
                pass

            # Insert fields of labels table
            try:
                for key, value in agent['labels'].items():
                    query = f"INSERT INTO labels ('id', 'key', 'value') VALUES " \
                            f"({agent['extra_params']['agent_id']}, '{key}', '{value}')"
                    # Send query to wdb
                    f.write(str(send_msg("global sql " + query)) + '\n')
            except KeyError:
                pass


def add_agent_group_relationships(agent_groups_file: str) -> None:
    def _create_agent_group_relationship(agent_id: int, group_ids: list) -> None:
        groups = ','.join([f'"{group_id}"' for group_id in group_ids])
        command = 'global set-agent-groups {"mode":"append","sync_status":"syncreq","data":[{"id":' \
                  f'{agent_id},"groups":[{groups}]' \
                  '}]}'

        send_msg(command)

    with open(agent_groups_file) as f:
        agent_group_relationships = yaml.safe_load(f)

    for agent, group_list in agent_group_relationships['agent_ids'].items():
        _create_agent_group_relationship(agent, group_list)


if __name__ == "__main__":
    create_and_send_query('/tmp_volume/configuration_files/master_only/agent_info.yaml')
    add_agent_group_relationships('/tmp_volume/configuration_files/master_only/agent_groups.yaml')
