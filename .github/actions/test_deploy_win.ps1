# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

$VERSION = Get-Content VERSION.json | Select-String '"version"' | ForEach-Object { $_ -match '"version": *"([^"]+)"' ; $matches[1] }
$MAJOR = $VERSION.Split('.')[0]
$MINOR = $VERSION.Split('.')[1]
$SHA= git rev-parse --short $args[0]

$TEST_ARRAY=@(
              @("WAZUH_MANAGER ", "1.1.1.1", "<address>", "</address>"),
              @("WAZUH_MANAGER_PORT ", "7777", "<port>", "</port>"),
              @("WAZUH_PROTOCOL ", "udp", "<protocol>", "</protocol>"),
              @("WAZUH_REGISTRATION_SERVER ", "2.2.2.2", "<manager_address>", "</manager_address>"),
              @("WAZUH_REGISTRATION_PORT ", "8888", "<port>", "</port>"),
              @("WAZUH_REGISTRATION_PASSWORD ", "password", "<password>", "</password>"),
              @("WAZUH_KEEP_ALIVE_INTERVAL ", "10", "<notify_time>", "</notify_time>"),
              @("WAZUH_TIME_RECONNECT ", "10", "<time-reconnect>", "</time-reconnect>"),
              @("WAZUH_REGISTRATION_CA ", "/var/ossec/etc/testsslmanager.cert", "<server_ca_path>", "</server_ca_path>"),
              @("WAZUH_REGISTRATION_CERTIFICATE ", "/var/ossec/etc/testsslmanager.cert", "<agent_certificate_path>", "</agent_certificate_path>"),
              @("WAZUH_REGISTRATION_KEY ", "/var/ossec/etc/testsslmanager.key", "<agent_key_path>", "</agent_key_path>"),
              @("WAZUH_AGENT_NAME ", "test-agent", "<agent_name>", "</agent_name>"),
              @("WAZUH_AGENT_GROUP ", "test-group", "<groups>", "</groups>"),
              @("ENROLLMENT_DELAY ", "10", "<delay_after_enrollment>", "</delay_after_enrollment>")
)

function install_wazuh($vars)
{

    Write-Output "Testing the following variables $vars"
    Start-Process  C:\Windows\System32\msiexec.exe -ArgumentList  "/i wazuh-agent-$VERSION-0.commit$SHA.msi /qn $vars" -wait

}

function remove_wazuh
{

    Start-Process  C:\Windows\System32\msiexec.exe -ArgumentList "/x wazuh-agent-$VERSION-commit$SHA.msi /qn" -wait

}

function test($vars)
{

  For ($i=0; $i -lt $TEST_ARRAY.Length; $i++) {
    if($vars.Contains($TEST_ARRAY[$i][0])) {
      if ( ($TEST_ARRAY[$i][0] -eq "WAZUH_MANAGER ") -OR ($TEST_ARRAY[$i][0] -eq "WAZUH_PROTOCOL ") ) {
        $LIST = $TEST_ARRAY[$i][1].split(",")
        For ($j=0; $j -lt $LIST.Length; $j++) {
          $SEL = Select-String -Path 'C:\Program Files (x86)\ossec-agent\ossec.conf' -Pattern "$($TEST_ARRAY[$i][2])$($LIST[$j])$($TEST_ARRAY[$i][3])"
          if($SEL -ne $null) {
            Write-Output "The variable $($TEST_ARRAY[$i][0]) is set correctly"
          }
          if($SEL -eq $null) {
            Write-Output "The variable $($TEST_ARRAY[$i][0]) is not set correctly"
            exit 1
          }
        }
      }
      ElseIf ( ($TEST_ARRAY[$i][0] -eq "WAZUH_REGISTRATION_PASSWORD ") ) {
        if (Test-Path 'C:\Program Files (x86)\ossec-agent\authd.pass'){
          $SEL = Select-String -Path 'C:\Program Files (x86)\ossec-agent\authd.pass' -Pattern "$($TEST_ARRAY[$i][1])"
          if($SEL -ne $null) {
            Write-Output "The variable $($TEST_ARRAY[$i][0]) is set correctly"
          }
          if($SEL -eq $null) {
            Write-Output "The variable $($TEST_ARRAY[$i][0]) is not set correctly"
            exit 1
          }
        }
        else
        {
          Write-Output "WAZUH_REGISTRATION_PASSWORD is not correct"
          exit 1
        }
      }
      Else {
        $SEL = Select-String -Path 'C:\Program Files (x86)\ossec-agent\ossec.conf' -Pattern "$($TEST_ARRAY[$i][2])$($TEST_ARRAY[$i][1])$($TEST_ARRAY[$i][3])"
        if($SEL -ne $null) {
          Write-Output "The variable $($TEST_ARRAY[$i][0]) is set correctly"
        }
        if($SEL -eq $null) {
          Write-Output "The variable $($TEST_ARRAY[$i][0]) is not set correctly"
          exit 1
        }
      }
    }
  }

}

Write-Output "Download package: https://s3.us-west-1.amazonaws.com/packages-dev.wazuh.com/warehouse/pullrequests/$MAJOR.$MINOR/windows/wazuh-agent-$VERSION-0.commit$SHA.msi"
Invoke-WebRequest -Uri "https://s3.us-west-1.amazonaws.com/packages-dev.wazuh.com/warehouse/pullrequests/$MAJOR.$MINOR/windows/wazuh-agent-$VERSION-0.commit$SHA.msi" -OutFile "wazuh-agent-$VERSION-0.commit$SHA.msi"

install_wazuh "WAZUH_MANAGER=1.1.1.1 WAZUH_MANAGER_PORT=7777 WAZUH_PROTOCOL=udp WAZUH_REGISTRATION_SERVER=2.2.2.2 WAZUH_REGISTRATION_PORT=8888 WAZUH_REGISTRATION_PASSWORD=password WAZUH_KEEP_ALIVE_INTERVAL=10 WAZUH_TIME_RECONNECT=10 WAZUH_REGISTRATION_CA=/var/ossec/etc/testsslmanager.cert WAZUH_REGISTRATION_CERTIFICATE=/var/ossec/etc/testsslmanager.cert WAZUH_REGISTRATION_KEY=/var/ossec/etc/testsslmanager.key WAZUH_AGENT_NAME=test-agent WAZUH_AGENT_GROUP=test-group ENROLLMENT_DELAY=10"
test "WAZUH_MANAGER WAZUH_MANAGER_PORT WAZUH_PROTOCOL WAZUH_REGISTRATION_SERVER WAZUH_REGISTRATION_PORT WAZUH_REGISTRATION_PASSWORD WAZUH_KEEP_ALIVE_INTERVAL WAZUH_TIME_RECONNECT WAZUH_REGISTRATION_CA WAZUH_REGISTRATION_CERTIFICATE WAZUH_REGISTRATION_KEY WAZUH_AGENT_NAME WAZUH_AGENT_GROUP ENROLLMENT_DELAY "
remove_wazuh

install_wazuh "WAZUH_MANAGER=1.1.1.1"
test "WAZUH_MANAGER "
remove_wazuh

install_wazuh "WAZUH_MANAGER_PORT=7777"
test "WAZUH_MANAGER_PORT "
remove_wazuh

install_wazuh "WAZUH_PROTOCOL=udp"
test "WAZUH_PROTOCOL "
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_SERVER=2.2.2.2"
test "WAZUH_REGISTRATION_SERVER "
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_PORT=8888"
test "WAZUH_REGISTRATION_PORT "
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_PASSWORD=password"
test "WAZUH_REGISTRATION_PASSWORD "
remove_wazuh

install_wazuh "WAZUH_KEEP_ALIVE_INTERVAL=10"
test "WAZUH_KEEP_ALIVE_INTERVAL "
remove_wazuh

install_wazuh "WAZUH_TIME_RECONNECT=10"
test "WAZUH_TIME_RECONNECT "
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_CA=/var/ossec/etc/testsslmanager.cert"
test "WAZUH_REGISTRATION_CA "
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_CERTIFICATE=/var/ossec/etc/testsslmanager.cert"
test "WAZUH_REGISTRATION_CERTIFICATE "
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_KEY=/var/ossec/etc/testsslmanager.key"
test "WAZUH_REGISTRATION_KEY "
remove_wazuh

install_wazuh "WAZUH_AGENT_NAME=test-agent"
test "WAZUH_AGENT_NAME "
remove_wazuh

install_wazuh "WAZUH_AGENT_GROUP=test-group"
test "WAZUH_AGENT_GROUP "
remove_wazuh

install_wazuh "ENROLLMENT_DELAY=10"
test "ENROLLMENT_DELAY "
remove_wazuh
