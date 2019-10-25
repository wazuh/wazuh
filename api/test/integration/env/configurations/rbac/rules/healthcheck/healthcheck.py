import os

os.system("/var/ossec/bin/ossec_control status > /tmp/output.txt")
check = os.popen("diff -q /tmp/output.txt /tmp/rules_rbac.txt").read()

if "differ" in check:
    exit(0)
else:
    exit(1)
