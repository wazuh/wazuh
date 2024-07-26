from enum import Enum
import sys

class Parser:

    def __init__(self) -> None:
        pass

    def get_queue(self, queue):
        return chr(queue)

    def get_agent_id(self, agent_id):
        return agent_id.zfill(3)

    def get_agent_name(self, agent_name):
        return agent_name.strip()

    def get_agent_ip(self, agent_ip):
        return agent_ip.strip().replace(':', '|:')

    def get_origin(self, origin):
        origin = origin.strip()
        return origin.replace(':', '|:')

    def get_header_ossec_format(self, queue, agent_id, agent_name, agent_ip, origin):
        full_location = self.get_full_location(agent_id, agent_name, agent_ip, origin)
        return "{}:{}".format(queue, full_location)

    def get_full_location(self, agent_id, agent_name, agent_ip, origin):
        agent_id = self.get_agent_id(agent_id)
        agent_name = self.get_agent_name(agent_name)
        agent_ip = self.get_agent_ip(agent_ip)
        origin = self.get_origin(origin)
        return "[{}] ({}) {}->{}".format(agent_id, agent_name, agent_ip, origin)

    def get_event_ossec_format(self, event, config):
        queue = self.get_queue(config['queue'])

        header = self.get_header_ossec_format(queue, config['agent_id'], config['agent_name'], config['agent_ip'], config['origin'])
        return "{}:{}".format(header, event)

