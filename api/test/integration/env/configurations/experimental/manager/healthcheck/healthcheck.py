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


def check_hotfix_database():
    conn = create_connection('000')
    cur = conn.cursor()
    cur.execute("SELECT * FROM sys_hotfixes")
    result = cur.fetchall()

    return 0 if result else 1


def get_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    check = os.popen("diff -q /tmp/output.txt /configuration_files/healthcheck/agent_control_check.txt").read()
    output = os.system("grep -q 'wazuh-modulesd:syscollector: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")
    db = check_hotfix_database()

    if "differ" not in check and output == 0 and db == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(get_health())
