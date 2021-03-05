<#
.Description
Tool for setting the configuration of your Wazuh agent.

.PARAMETER config_group
 Select the group of settings to modify:
    enroll: Configure enrollment and server connection settings
.PARAMETER address
 Wazuh manager address
.PARAMETER port
 Wazuh manager port
.PARAMETER protocol
 Wazuh manager protocol
.PARAMETER registration-address
 Wazuh registration address
.PARAMETER registration-port
 Wazuh registration port
.PARAMETER token
 Wazuh registration password
.PARAMETER keep-alive
 Wazuh agent keep alive time
.PARAMETER reconnection-time
 Wazuh agent reconnection time
.PARAMETER registration-ca
 Certification Authority (CA) path
.PARAMETER registration-certificate 
 Registration certificate path
.PARAMETER registration-key
 Registration key path
.PARAMETER name
 Wazuh agent name
.PARAMETER group
 Wazuh agent group

 .example
 Set Wazuh Manager address and register
./wazuhctl.ps1 enroll -address [MANAGER_ADDRESS]

 .example
 Set Wazuh Manager address and register to a different manager
./wazuhctl.ps1 enroll -address [MANAGER_ADDRESS] -registration-address [REGISTRATION_ADDRESS]

 .example
 Set Wazuh Manager address and register using password
./wazuhctl.ps1 enroll -address [MANAGER_ADDRESS] -token [PASSWORD]
#> 

param (
    [parameter (Mandatory=$true, Position=0)] [ValidateSet("enroll")] [string] ${config_group},
    [string[]]${address},
    [ValidateRange(1, 65535)] [string]${port},
    [ValidateSet("tcp", "udp")][string]${protocol},
    [string]${registration-address},
    [ValidateRange(1, 65535)] [string]${registration-port},
    [string]${token},
    [ValidateRange(1, [int]::MaxValue)] [string]${keep-alive},
    [ValidateRange(1, [int]::MaxValue)] [string]${reconnection-time},
    [ValidateScript({Test-Path $_})] [string]${registration-ca},
    [ValidateScript({Test-Path $_})] [string]${registration-certificate},
    [ValidateScript({Test-Path $_})] [string]${registration-key},
    [string]${name},
    [string]${group}
)

[string]${basedir} = (split-path -parent $MyInvocation.MyCommand.Definition)
[string]${ossecconf} = ${basedir} + "\ossec.conf"

${xml_conf} = [xml](Get-Content -Path ${ossecconf})

if ($config_group -eq "enroll") { 
    if (${address}) {    
        # Remove old server configuration
        (${xml_conf}.ossec_config.client.SelectNodes("server")) | ForEach-Object {
            [void]$_.ParentNode.RemoveChild($_)
        }

        # Set new server configuration
        $client = ${xml_conf}.ossec_config.SelectSingleNode("client")

        if (${reconnection-time}) { 
            if ($client."time-reconnect") {
                $client."time-reconnect" = ${reconnection-time} 
            }
            else 
            {
                $reconnect_element = ${xml_conf}.CreateElement("time-reconnect")
                $client.AppendChild($reconnect_element) | Out-Null
                $client."time-reconnect" = ${reconnection-time} 
            }
        }

        if (${keep-alive}) { 
            if ($client.notify_time) {
                $client.notify_time = ${keep-alive}
            }
            else 
            {
                $notify_element = ${xml_conf}.CreateElement("notify_time")
                $client.AppendChild($notify_element) | Out-Null
                $client.notify_time = ${keep-alive}
            }
        }

        ${address} | ForEach-Object {
            $server_element = ${xml_conf}.CreateElement("server")
            $client.AppendChild($server_element) | Out-Null
        }
    }

    $i = 0
    (${xml_conf}.ossec_config.client.SelectNodes("server")) | ForEach-Object {
        $address_element = ${xml_conf}.CreateElement("address")
        $port_element = ${xml_conf}.CreateElement("port")
        $protocol_element = ${xml_conf}.CreateElement("protocol")
        
        if (${address}) { 
            [void]$_.AppendChild($address_element)
            [void]$_.AppendChild($port_element)
            [void]$_.AppendChild($protocol_element)
            $_.address = ${address}[$i] 
        }

        if (${port}) { $_.port = ${port} }
        elseif (${address}) { $_.port = "1514" }
        
        if (${protocol}) { $_.protocol = ${protocol} }
        elseif (${address}) { $_.protocol = "tcp" }

        if (${protocol}) { $_.protocol = ${protocol} }
        elseif (${address}) { $_.protocol = "tcp" }
        
        $i=$i+1
    }

    if (${registration-address} -or ${registration-port} -or ${token} -or 
        ${registration-ca} -or ${registration-certificate} -or 
        ${registration-key} -or ${name} -or ${group}){
        # Remove old autoenrolment configuration
        (${xml_conf}.ossec_config.client.SelectNodes("enrollment")) | ForEach-Object {
            [void]$_.ParentNode.RemoveChild($_)
        }

        $enrollment_element = ${xml_conf}.CreateElement("enrollment")
        $client = ${xml_conf}.ossec_config.SelectSingleNode("client")
        $client.AppendChild($enrollment_element)
        $enrollment = $client.SelectSingleNode("enrollment")

        $enabled = ${xml_conf}.CreateElement("enabled")
        $enrollment.AppendChild($enabled)
        $enrollment.enabled = "yes"
        
        if (${registration-address}){
            $element = ${xml_conf}.CreateElement("manager_address")
            $enrollment.AppendChild($element) | Out-Null
            $enrollment.manager_address = ${registration-address}
        }
        if (${registration-port}){
            $element = ${xml_conf}.CreateElement("port")
            $enrollment.AppendChild($element) | Out-Null
            $enrollment.port = ${registration-port}
        }
        if (${token}){
            $element = ${xml_conf}.CreateElement("authorization_pass")
            $enrollment.AppendChild($element) | Out-Null
            $enrollment.authorization_pass = ${token}
        }
        if (${registration-ca}){
            $element = ${xml_conf}.CreateElement("server_ca_path")
            $enrollment.AppendChild($element) | Out-Null
            $enrollment.server_ca_path = ${registration-ca}
        }
        if (${registration-certificate}){
            $element = ${xml_conf}.CreateElement("agent_certificate_path")
            $enrollment.AppendChild($element) | Out-Null
            $enrollment.agent_certificate_path = ${registration-certificate}
        }
        if (${registration-key}){
            $element = ${xml_conf}.CreateElement("agent_key_path")
            $enrollment.AppendChild($element) | Out-Null
            $enrollment.agent_key_path = ${registration-key}
        }
        if (${name}){
            $element = ${xml_conf}.CreateElement("agent_name")
            $enrollment.AppendChild($element) | Out-Null
            $enrollment.agent_name = ${name}
        }
        if (${group}){
            $element = ${xml_conf}.CreateElement("groups")
            $enrollment.AppendChild($element) | Out-Null
            $enrollment.groups = ${group}
        }
    }
}
${xml_conf}.Save(${ossecconf})