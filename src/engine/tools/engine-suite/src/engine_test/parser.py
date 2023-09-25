from enum import Enum
import sys

class Parser:
    def get_queue(queue):
        return chr(queue)

    def get_agent_id(agent_id):
        return agent_id.zfill(3)

    def get_agent_name(agent_name):
        return agent_name.strip()

    def get_agent_ip(agent_ip):
        return agent_ip.strip().replace(':', '|:')

    def get_origin(origin):
        origin = origin.strip()
        return origin.replace(':', '|:')

    def get_header_ossec_format(queue, agent_id, agent_name, agent_ip, origin):
        full_location = Parser.get_full_location(agent_id, agent_name, agent_ip, origin)
        return "{}:{}".format(queue, full_location)

    def get_full_location(agent_id, agent_name, agent_ip, origin):
        agent_id = Parser.get_agent_id(agent_id)
        agent_name = Parser.get_agent_name(agent_name)
        agent_ip = Parser.get_agent_ip(agent_ip)
        origin = Parser.get_origin(origin)
        return "[{}] ({}) {}->{}".format(agent_id, agent_name, agent_ip, origin)

    def get_event_ossec_format(event, config):
        queue = Parser.get_queue(config['queue'])

        header = Parser.get_header_ossec_format(queue, config['agent_id'], config['agent_name'], config['agent_ip'], config['origin'])
        return "{}:{}".format(header, event)

    def parse_syslog_format(event):
        if len(event) > 5 and event[0] == '<':
            return event[5:len(event)]
        else:
            return event