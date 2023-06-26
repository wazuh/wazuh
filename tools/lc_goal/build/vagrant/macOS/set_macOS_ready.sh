#!/bin/bash

vmname=$1

VBoxManage modifyvm $vmname --cpuidset 00000001 000106e5 00100800 0098e3fd bfebfbff

VBoxManage modifyvm $vmname --cpu-profile "Intel Core i7-6700K"

VBoxManage setextradata $vmname "VBoxInternal/Devices/efi/0/Config/DmiSystemProduct" "iMac11,3"

VBoxManage setextradata $vmname "VBoxInternal/Devices/efi/0/Config/DmiSystemVersion" "1.0"

VBoxManage setextradata $vmname "VBoxInternal/Devices/efi/0/Config/DmiBoardProduct" "Hackboard"

VBoxManage setextradata $vmname "VBoxInternal/Devices/smc/0/Config/DeviceKey" "ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc"

VBoxManage setextradata $vmname "VBoxInternal/Devices/smc/0/Config/GetKeyFromRealSMC" 1

VBoxManage setextradata $vmname "VBoxInternal2/EfiGraphicsResolution" "1920x1080"
