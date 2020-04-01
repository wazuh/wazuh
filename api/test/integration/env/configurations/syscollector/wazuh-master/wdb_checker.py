import os
import subprocess
import time


wdb_socket = '/var/ossec/queue/db/wdb'

while not os.path.exists(wdb_socket):
    time.sleep(5)

query = "agent 000 sql insert or ignore into sys_hotfixes(scan_id, scan_time, hotfix) values (1408519641, '2019/08/05 12:06:26', 'KB2533552')"
subprocess.check_call(['/var/ossec/framework/python/bin/python3', '/send_to_wdb.py', '-q', query])

