#!/usr/bin/env sh

#
# CIS-CAT Script Check Engine
# 
# Name       Date       Description
# -------------------------------------------------------------------
# B. Munyan  7/20/16    Ensure no users have a password warning period < 7
# 

output=$(
/usr/bin/getent shadow | awk -F : 'match($2, /^[^!*]/) && $6 < 7 { print "User " $1 " password warning period < 7 (" $6 ")"}' 2>/dev/null
)

# we captured output of the subshell, let's interpret it
if [ "$output" == "" ] ; then
    exit $XCCDF_RESULT_PASS
else
    # print the reason why we are failing
    echo "$output"
    exit $XCCDF_RESULT_FAIL
fi
