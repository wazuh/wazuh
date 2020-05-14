import os
import subprocess
import time

from datetime import datetime

wdb_socket = '/var/ossec/queue/db/wdb'
timeout = 60

now = datetime.now()
while not os.path.exists(wdb_socket):
    if (datetime.now() - now).seconds > timeout:
        raise TimeoutError
    time.sleep(5)

query = "agent 000 sql insert or ignore into sys_hotfixes(scan_id, scan_time, hotfix) values (1408519641, '2019/08/05 12:06:26', 'KB2533552')"
subprocess.check_call(['/var/ossec/framework/python/bin/python3', '/configuration_files/send_to_wdb.py', '-q', query])
