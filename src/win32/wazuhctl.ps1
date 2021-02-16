<#
.Description
Tool for setting the configuration of your Wazuh agent.

.PARAMETER enroll
 Configure enrollment and server connection settings
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
    [switch]${enroll},
    [string[]]${address},
    [string]${port},
    [string]${protocol},
    [string]${registration-address},
    [string]${registration-port},
    [string]${token},
    [string]${keep-alive},
    [string]${reconnection-time},
    [string]${registration-ca},
    [string]${registration-certificate},
    [string]${registration-key},
    [string]${name},
    [string]${group}
)

[string]${basedir} = (split-path -parent $MyInvocation.MyCommand.Definition)
[string]${ossecconf} = ${basedir} + "\ossec.conf"

${xml_conf} = [xml](Get-Content -Path ${ossecconf})

if (${enroll}) { 
    if (${address}) {    
        # Remove old server configuration
        (${xml_conf}.ossec_config.client.SelectNodes("server")) | ForEach-Object {
            [void]$_.ParentNode.RemoveChild($_)
        }

        # Set new server configuration
        $client = ${xml_conf}.ossec_config.SelectSingleNode("client")
        ${address} | ForEach-Object {
            $server_element = ${xml_conf}.CreateElement("server")
            $client.AppendChild($server_element)
        }
    }

    $i = 0
    (${xml_conf}.ossec_config.client.SelectNodes("server")) | ForEach-Object {
        $address_element = ${xml_conf}.CreateElement("address")
        $port_element = ${xml_conf}.CreateElement("port")
        $protocol_element = ${xml_conf}.CreateElement("protocol")
        $keep_alive_element = ${xml_conf}.CreateElement("notify_time")
        $time_reconnect_element = ${xml_conf}.CreateElement("time-reconnect")
        
        if (${address}) { 
            [void]$_.AppendChild($address_element)
            [void]$_.AppendChild($port_element)
            [void]$_.AppendChild($protocol_element)
            [void]$_.AppendChild($keep_alive_element)
            [void]$_.AppendChild($time_reconnect_element)
            $_.address = ${address}[$i] 
        }

        if (${port}) { $_.port = ${port} }
        elseif (${address}) { $_.port = "1514" }
        
        if (${protocol}) { $_.protocol = ${protocol} }
        elseif (${address}) { $_.protocol = "tcp" }

        if (${protocol}) { $_.protocol = ${protocol} }
        elseif (${address}) { $_.protocol = "tcp" }

        if (${reconnection-time}) { $_."time-reconnect" = ${reconnection-time} }
        elseif (${address}) { $_."time-reconnect" = "60" }

        if (${keep-alive}) { $_.notify_time = ${keep-alive} }
        elseif (${address}) { $_.notify_time = "10" }
        
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
            $enrollment.AppendChild($element)
            $enrollment.manager_address = ${registration-address}
        }
        if (${registration-port}){
            $element = ${xml_conf}.CreateElement("port")
            $enrollment.AppendChild($element)
            $enrollment.port = ${registration-port}
        }
        if (${token}){
            $element = ${xml_conf}.CreateElement("authorization_pass")
            $enrollment.AppendChild($element)
            $enrollment.authorization_pass = ${token}
        }
        if (${registration-ca}){
            $element = ${xml_conf}.CreateElement("server_ca_path")
            $enrollment.AppendChild($element)
            $enrollment.server_ca_path = ${registration-ca}
        }
        if (${registration-certificate}){
            $element = ${xml_conf}.CreateElement("agent_certificate_path")
            $enrollment.AppendChild($element)
            $enrollment.agent_certificate_path = ${registration-certificate}
        }
        if (${registration-key}){
            $element = ${xml_conf}.CreateElement("agent_key_path")
            $enrollment.AppendChild($element)
            $enrollment.agent_key_path = ${registration-key}
        }
        if (${name}){
            $element = ${xml_conf}.CreateElement("agent_name")
            $enrollment.AppendChild($element)
            $enrollment.agent_name = ${name}
        }
        if (${group}){
            $element = ${xml_conf}.CreateElement("groups")
            $enrollment.AppendChild($element)
            $enrollment.groups = ${group}
        }
    }
}
${xml_conf}.Save(${ossecconf})