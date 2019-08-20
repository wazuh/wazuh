#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name       Date       Description
# -------------------------------------------------------------------
# B. Munyan  7/13/16    Ensure no world-writable files exist
# B. Munyan  2/07/17    Eliminate /sys from this check as well
# 

output=$(
find / -path /proc -prune -o -path /sys -prune -o -type f -perm -0002 -printf "World-Writable file %p\n" 2>/dev/null
)

# we captured output of the subshell, let's interpret it
if [ "$output" == "" ] ; then
    exit $XCCDF_RESULT_PASS
else
    # print the reason why we are failing
    echo "$output"
    exit $XCCDF_RESULT_FAIL
fi
