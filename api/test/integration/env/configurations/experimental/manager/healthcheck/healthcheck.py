import os
import sqlite3
import time


database = '/var/ossec/queue/db/'


def create_connection(agent_id):
    agent_db = f"{database}{agent_id}.db"
    conn = None
    try:
        conn = sqlite3.connect(agent_db)
    except sqlite3.Error as e:
        print(e)

    return conn


def get_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    check0 = os.popen("diff -q /tmp/output.txt /configuration_files/healthcheck/agent_control_check.txt").read()
    check1 = os.system("grep -q 'wazuh-modulesd:syscollector: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")
    check2 = 0 if os.system("grep -qs 'Listening on ' /var/ossec/logs/api.log") == 0 else 1

    if "differ" not in check0 and check1 == 0 and check2 == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(get_health())
