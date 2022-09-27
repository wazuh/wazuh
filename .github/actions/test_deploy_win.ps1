$VERSION = Get-Content src/VERSION
[version]$VERSION = $VERSION -replace '[v]',''
$MAJOR=$VERSION.Major
$MINOR=$VERSION.Minor
$SHA= git rev-parse --short HEAD

$WAZUH_MANAGER="1.1.1.1"
$WAZUH_MANAGER_PORT="7777"
$WAZUH_PROTOCOL="udp"
$WAZUH_REGISTRATION_SERVER="2.2.2.2"
$WAZUH_REGISTRATION_PORT="8888"
$WAZUH_REGISTRATION_PASSWORD="password"
$WAZUH_KEEP_ALIVE_INTERVAL="10"
$WAZUH_TIME_RECONNECT="10"
$WAZUH_REGISTRATION_CA="/var/ossec/etc/testsslmanager.cert"
$WAZUH_REGISTRATION_CERTIFICATE="/var/ossec/etc/testsslmanager.cert"
$WAZUH_REGISTRATION_KEY="/var/ossec/etc/testsslmanager.key"
$WAZUH_AGENT_NAME="test-agent"
$WAZUH_AGENT_GROUP="test-group"
$ENROLLMENT_DELAY="10"

function install_wazuh($vars)
{
    Write-Output "Testing the following variables $vars"
    msiexec.exe /i wazuh-agent-$VERSION-commit$SHA.msi /qn $vars

function remove_wazuh
{
    msiexec.exe /x wazuh-agent-$VERSION-commit$SHA.msi /qn
}

function test($vars)
{

  if($vars.Contains("WAZUH_MANAGER=")) {
    $ADDRESSES = $WAZUH_MANAGER.split(",")
    For ($i=0; $i -lt $ADDRESSES.Length; $i++) {
      $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<address>${ADDRESSES[i]}</address>"
      if($SEL -ne $null) {
        Write-Output "WAZUH_MANAGER is correct"
      }
      if($SEL -eq $null) {
        Write-Output "WAZUH_MANAGER is not correct"
        exit 1
      }
    }
  }
  if($vars.Contains("WAZUH_MANAGER_PORT=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<port>$WAZUH_MANAGER_PORT</port>"
    if($SEL -ne $null) {
      Write-Output "WAZUH_MANAGER_PORT is correct"
    }
    if($SEL -eq $null) {
      Write-Output "WAZUH_MANAGER_PORT is not correct"
      exit 1
    }
  }
  if($vars.Contains("WAZUH_PROTOCOL=")) {
    $PROTOCOLS = $WAZUH_PROTOCOL.split(",")
    For ($i=0; $i -lt $PROTOCOLS.Length; $i++) {
      $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<protocol>$PROTOCOLS[i]</protocol>"
      if($SEL -ne $null) {
        Write-Output "WAZUH_PROTOCOL is correct"
      }
      if($SEL -eq $null) {
        Write-Output "WAZUH_PROTOCOL is not correct"
        exit 1
      }
    }
  }
  if($vars.Contains("WAZUH_REGISTRATION_SERVER=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<manager_address>$WAZUH_REGISTRATION_SERVER</manager_address>"
    if($SEL -ne $null) {
      Write-Output "WAZUH_REGISTRATION_SERVER is correct"
    }
    if($SEL -eq $null) {
      Write-Output "WAZUH_REGISTRATION_SERVER is not correct"
      exit 1
    }
  }
  if($vars.Contains("WAZUH_REGISTRATION_PORT=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<port>$WAZUH_REGISTRATION_PORT</port>"
    if($SEL -ne $null) {
      Write-Output "WAZUH_REGISTRATION_PORT is correct"
    }
    if($SEL -eq $null) {
      Write-Output "WAZUH_REGISTRATION_PORT is not correct"
      exit 1
    }
  }
  if($vars.Contains("WAZUH_REGISTRATION_PASSWORD=")) {
    if (Test-Path 'C:\Program Files(x86)\wazuh-agent\authd.pass'){
      $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\authd.pass' -Pattern "$WAZUH_REGISTRATION_PASSWORD"
      if($SEL -ne $null) {
        Write-Output "WAZUH_REGISTRATION_PASSWORD is correct"
      }
      if($SEL -eq $null) {
        Write-Output "WAZUH_REGISTRATION_PASSWORD is not correct"
        exit 1
      }
    }
    else
    {
      Write-Output "WAZUH_REGISTRATION_PASSWORD is not correct"
      exit 1
    }
  }
  if($vars.Contains("WAZUH_KEEP_ALIVE_INTERVAL=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<notify_time>$WAZUH_KEEP_ALIVE_INTERVAL</notify_time>"
    if($SEL -ne $null) {
      Write-Output "WAZUH_KEEP_ALIVE_INTERVAL is correct"
    }
    if($SEL -eq $null) {
      Write-Output "WAZUH_KEEP_ALIVE_INTERVAL is not correct"
      exit 1
    }
  }
  if($vars.Contains("TIME_RECONNECT=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<time-reconnect>$TIME_RECONNECT</time-reconnect>"
    if($SEL -ne $null) {
      Write-Output "TIME_RECONNECT is correct"
    }
    if($SEL -eq $null) {
      Write-Output "TIME_RECONNECT is not correct"
      exit 1
    }
  }
  if($vars.Contains("WAZUH_REGISTRATION_CA=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<server_ca_path>$WAZUH_REGISTRATION_CA</server_ca_path>"
    if($SEL -ne $null) {
      Write-Output "WAZUH_REGISTRATION_CA is correct"
    }
    if($SEL -eq $null) {
      Write-Output "WAZUH_REGISTRATION_CA is not correct"
      exit 1
    }
  }
  if($vars.Contains("WAZUH_REGISTRATION_CERTIFICATE=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<agent_certificate_path>$WAZUH_REGISTRATION_CERT</agent_agent_certificate_pathcert_path>"
    if($SEL -ne $null) {
      Write-Output "WAZUH_REGISTRATION_CERTIFICATE is correct"
    }
    if($SEL -eq $null) {
      Write-Output "WAZUH_REGISTRATION_CERTIFICATE is not correct"
      exit 1
    }
  }
  if($vars.Contains("WAZUH_REGISTRATION_KEY=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<agent_key_path>$WAZUH_REGISTRATION_KEY</agent_key_path>"
    if($SEL -ne $null) {
      Write-Output "WAZUH_REGISTRATION_KEY is correct"
    }
    if($SEL -eq $null) {
      Write-Output "WAZUH_REGISTRATION_KEY is not correct"
      exit 1
    }
  }
  if($vars.Contains("WAZUH_AGENT_NAME=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<agent_name>$WAZUH_AGENT_NAME</agent_name>"
    if($SEL -ne $null) {
      Write-Output "WAZUH_AGENT_NAME is correct"
    }
    if($SEL -eq $null) {
      Write-Output "WAZUH_AGENT_NAME is not correct"
      exit 1
    }
  }
  if($vars.Contains("WAZUH_AGENT_GROUP=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<groups>$WAZUH_AGENT_GROUP</groups>"
    if($SEL -ne $null) {
      Write-Output "WAZUH_AGENT_GROUP is correct"
    }
    if($SEL -eq $null) {
      Write-Output "WAZUH_AGENT_GROUP is not correct"
      exit 1
    }
  }
  if($vars.Contains("ENROLLMENT_DELAY=")) {
    $SEL = Select-String -Path 'C:\Program Files(x86)\wazuh-agent\ossec.conf' -Pattern "<delay_after_enrollment>$ENROLLMENT_AGENT</delay_after_enrollment>"
    if($SEL -ne $null) {
      Write-Output "ENROLLMENT_DELAY is correct"
    }
    if($SEL -eq $null) {
      Write-Output "ENROLLMENT_DELAY is not correct"
      exit 1
    }
  }
}

wget "https://s3.us-west-1.amazonaws.com/packages-dev.wazuh.com/warehouse/pullrequests/$MAJOR.$MINOR/windows/wazuh-agent-$VERSION-commit$SHA.msi" -OutFile "wazuh-agent-$VERSION-commit$SHA.msi"

install_wazuh "WAZUH_MANAGER=1.1.1.1 WAZUH_MANAGER_PORT=7777 WAZUH_PROTOCOL=udp WAZUH_REGISTRATION_SERVER=2.2.2.2 WAZUH_REGISTRATION_PORT=8888 WAZUH_REGISTRATION_PASSWORD=password WAZUH_KEEP_ALIVE_INTERVAL=10 WAZUH_TIME_RECONNECT=10 WAZUH_REGISTRATION_CA=/var/ossec/etc/testsslmanager.cert WAZUH_REGISTRATION_CERTIFICATE=/var/ossec/etc/testsslmanager.cert WAZUH_REGISTRATION_KEY=/var/ossec/etc/testsslmanager.key WAZUH_AGENT_NAME=test-agent WAZUH_AGENT_GROUP=test-group ENROLLMENT_DELAY=10" 
test "WAZUH_MANAGER WAZUH_MANAGER_PORT WAZUH_PROTOCOL WAZUH_REGISTRATION_SERVER WAZUH_REGISTRATION_PORT WAZUH_REGISTRATION_PASSWORD WAZUH_KEEP_ALIVE_INTERVAL WAZUH_TIME_RECONNECT WAZUH_REGISTRATION_CA WAZUH_REGISTRATION_CERTIFICATE WAZUH_REGISTRATION_KEY WAZUH_AGENT_NAME WAZUH_AGENT_GROUP ENROLLMENT_DELAY" 
remove_wazuh

install_wazuh "WAZUH_MANAGER=1.1.1.1"
test "WAZUH_MANAGER"
remove_wazuh

install_wazuh "WAZUH_MANAGER_PORT=7777"
test "WAZUH_MANAGER_PORT"
remove_wazuh

install_wazuh "WAZUH_PROTOCOL=udp"
test "WAZUH_PROTOCOL"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_SERVER=2.2.2.2"
test "WAZUH_REGISTRATION_SERVER"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_PORT=8888"
test "WAZUH_REGISTRATION_PORT"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_PASSWORD=password"
test "WAZUH_REGISTRATION_PASSWORD"
remove_wazuh

install_wazuh "WAZUH_KEEP_ALIVE_INTERVAL=10"
test "WAZUH_KEEP_ALIVE_INTERVAL"
remove_wazuh

install_wazuh "WAZUH_TIME_RECONNECT=10"
test "WAZUH_TIME_RECONNECT"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_CA=/var/ossec/etc/testsslmanager.cert"
test "WAZUH_REGISTRATION_CA"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_CERTIFICATE=/var/ossec/etc/testsslmanager.cert"
test "WAZUH_REGISTRATION_CERTIFICATE"
remove_wazuh

install_wazuh "WAZUH_REGISTRATION_KEY=/var/ossec/etc/testsslmanager.key"
test "WAZUH_REGISTRATION_KEY"
remove_wazuh

install_wazuh "WAZUH_AGENT_NAME=test-agent"
test "WAZUH_AGENT_NAME"
remove_wazuh

install_wazuh "WAZUH_AGENT_GROUP=test-group"
test "WAZUH_AGENT_GROUP"
remove_wazuh

install_wazuh "ENROLLMENT_DELAY=10"
test "ENROLLMENT_DELAY"
remove_wazuh