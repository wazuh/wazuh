#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name       Date       Description
# -------------------------------------------------------------------
# B. Munyan  7/20/16    Ensure no users have a password inactivity period > 30
# 

output=$(
/usr/bin/getent shadow | awk -F : 'match($2, /^[^!*]/) && ($7 == "" || $7 > 30) { if ($7 == "") { print "User " $1 " password inactivity period is not defined" } else { print "User " $1 " Password Inactivity Period > 30 (" $7 ")" } }'
)

# we captured output of the subshell, let's interpret it
if [ "$output" == "" ] ; then
    exit $XCCDF_RESULT_PASS
else
    # print the reason why we are failing
    echo "$output"
    exit $XCCDF_RESULT_FAIL
fi
