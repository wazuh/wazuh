import os

os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
check = os.popen("diff -q /tmp/output.txt /tmp/agent_control_check.txt").read()

if "differ" in check:
    exit(0)
else:
    exit(1)
