import os
import sqlite3


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
    check = os.popen("diff -q /tmp/output.txt /configuration_files/healthcheck/agent_control_check.txt").read()
    output = os.system("grep -q 'wazuh-modulesd:syscollector: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")

    if "differ" not in check and output == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(get_health())
