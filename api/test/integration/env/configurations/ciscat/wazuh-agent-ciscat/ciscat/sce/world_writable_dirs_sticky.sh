#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name       Date       Description
# -------------------------------------------------------------------
# B. Munyan  7/13/16    Sticky bit must be on all world-writable dirs
# 

PATH=/bin:/usr/bin

output=$(
find / -path /proc -prune -o -type d \( -perm -0002 -a ! -perm -1000 \) -printf "%p is %m should be 1777\n" 2>/dev/null
)

# we captured output of the subshell, let's interpret it
if [ "$output" == "" ] ; then
    exit $XCCDF_RESULT_PASS
else
    # print the reason why we are failing
    echo "$output"
    exit $XCCDF_RESULT_FAIL
fi
