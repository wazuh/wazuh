import os

os.system("/var/ossec/bin/ossec_control status > /tmp/daemons.txt")
check = os.popen("diff -q /tmp/daemons.txt /tmp/daemons_check.txt").read()

if "differ" in check:
    exit(0)
else:
    exit(1)
