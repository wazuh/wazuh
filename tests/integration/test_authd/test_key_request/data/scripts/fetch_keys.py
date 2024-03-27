#!/usr/bin/env python

import json
import sys
import time

keys_db = [
    {
        # Agent 001 id configuration
        'id': '001',
        'ip': 'any',
        'name': 'wazuh_agent1',
        'key': '675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c911'
    },
    {
        # Agent 002 ip/id configuration
        'id': '002',
        'ip': '10.10.10.10',
        'name': 'wazuh_agent2',
        'key': '675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c912'
    },
    {
        # Agent 003 basic conf
        'id': '003',
        'ip': 'any',
        'name': 'wazuh_agent3',
        'key': '3333333333333333333333333333333333333333333333333333333333333333'
    },
    {
        # Agent 005 basic conf
        'id': '005',
        'ip': 'any',
        'name': 'wazuh_agent5',
        'key': '5555555555555555555555555555555555555555555555555555555555555555'
    },
    {
        # Agent 006 - Empty key
        'id': '006',
        'ip': 'any',
        'name': 'wazuh_agent6',
        'key': ''
    },
    {
        # Agent 007 - Error 5
        'id': '007',
        'ip': 'any',
        'name': 'wazuh_agent7',
        'key': '7777777777777777777777777777777777777777777777777777777777777777'
    },
    {
        # Agent 007 - Error 5
        'id': '007',
        'ip': 'any',
        'name': 'wazuh_agent7',
        'key': '7777777777777777777777777777777777777777777777777777777777777777'
    }
]


keys_db_sleep = [
    {
        # Agent 001 id configuration
        'id': '001',
        'ip': 'any',
        'name': 'wazuh_agent1',
        'key': '675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c911'
    },
    {
        # Agent 002 ip/id configuration
        'id': '002',
        'ip': '10.10.10.10',
        'name': 'wazuh_agent2',
        'key': '675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c912'
    },
    {
        # Agent 003 basic conf
        'id': '003',
        'ip': 'any',
        'name': 'wazuh_agent3',
        'key': '3333333333333333333333333333333333333333333333333333333333333333'
    }
]


def main(keys):
    """This file regenerate the agent key after a manipulation of it
    Print the legacy key of the agent, this way the agent key polling module can set the correct key again.
    """
    if len(sys.argv) < 3:
        print(json.dumps({"error": 1, "message": "Too few arguments"}))
        return

    try:
        value = sys.argv[2]
        data = list(
            (filter(lambda agent: agent[sys.argv[1]] == value, keys)))
        if len(data) == 1:
            print(json.dumps({"error": 0, "data": data[0]}))
        elif len(data) > 1:
            print(json.dumps(
                {"error": 5, "message": f"Found more than one match for required {sys.argv[1]}"}))
        else:
            print(json.dumps({"error": 4, "message": "No agent key found"}))
    except KeyError:
        print(json.dumps({"error": 3, "message": "Bad arguments given"}))
        return
    except Exception as e:
        print(json.dumps({"error": 2, "message": str(e)}))
        return


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "-s":
        del sys.argv[1]
        time.sleep(5)
        main(keys_db_sleep)
    else:
        main(keys_db)
