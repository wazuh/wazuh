#!/bin/sh

# Add an IP to the hosts.deny file

USER=$1
IP=$2

if [ "x${IP}" = "x" ]; then
   exit 1;
fi

echo "ALL:${IP}" >> /etc/hosts.deny

