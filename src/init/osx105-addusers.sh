#! /bin/sh
# By Spransy, Derek" <DSPRANS () emory ! edu> and Charlie Scott



# Creating the groups.
sudo dscl localhost -create /Local/Default/Groups/ossec
sudo dscl localhost -createprop /Local/Default/Groups/ossec PrimaryGroupID 600
sudo dscl localhost -createprop /Local/Default/Groups/ossec RealName ossec
sudo dscl localhost -createprop /Local/Default/Groups/ossec RecordName ossec
sudo dscl localhost -createprop /Local/Default/Groups/ossec RecordType: dsRecTypeStandard:Groups
sudo dscl localhost -createprop /Local/Default/Groups/ossec Password "*"


# Creating the users.
sudo dscl localhost -create /Local/Default/Users/ossec
sudo dscl localhost -createprop /Local/Default/Users/ossec RecordName ossec
sudo dscl localhost -createprop /Local/Default/Users/ossec RealName "ossecacct"
sudo dscl localhost -createprop /Local/Default/Users/ossec NFSHomeDirectory /var/ossec
sudo dscl localhost -createprop /Local/Default/Users/ossec UniqueID 600
sudo dscl localhost -createprop /Local/Default/Users/ossec PrimaryGroupID 600
sudo dscl localhost -createprop /Local/Default/Users/ossec Password "*"

sudo dscl localhost -create /Local/Default/Users/ossecm
sudo dscl localhost -createprop /Local/Default/Users/ossecm RecordName ossecm
sudo dscl localhost -createprop /Local/Default/Users/ossecm RealName "ossecmacct"
sudo dscl localhost -createprop /Local/Default/Users/ossecm NFSHomeDirectory /var/ossec
sudo dscl localhost -createprop /Local/Default/Users/ossecm UniqueID 601
sudo dscl localhost -createprop /Local/Default/Users/ossecm PrimaryGroupID 600
sudo dscl localhost -createprop /Local/Default/Users/ossecm Password "*"

sudo dscl localhost -create /Local/Default/Users/ossecr
sudo dscl localhost -createprop /Local/Default/Users/ossecr RecordName ossecr
sudo dscl localhost -createprop /Local/Default/Users/ossecr RealName "ossecracct"
sudo dscl localhost -createprop /Local/Default/Users/ossecr NFSHomeDirectory /var/ossec
sudo dscl localhost -createprop /Local/Default/Users/ossecr UniqueID 602
sudo dscl localhost -createprop /Local/Default/Users/ossecr PrimaryGroupID 600
sudo dscl localhost -createprop /Local/Default/Users/ossecr Password "*"

