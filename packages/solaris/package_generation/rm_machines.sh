#!/bin/bash
# remove vagrant machines script
# Wazuh, Inc 2015

machine_id=`vboxmanage list vms | grep ${1} | cut -d "{" -f2 | cut -d "}" -f1`

if [ ! -z "$machine_id" ]; then
    VBoxManage list runningvms | grep $1
    if [ $? -eq 0 ]; then
	vboxmanage controlvm $machine_id poweroff soft
    fi
    vboxmanage unregistervm --delete $machine_id
fi
