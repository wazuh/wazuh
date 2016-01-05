# WAZUH Windows Add Agent Script

# v2.1 2015/01/05
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
param (
	#Mandatory
	[switch]$Elevated,
    [string]$api_ip = "",
    [string]$username = "",
    [string]$password = "",
	
	#Optionals
	[string]$api_port = "55000",
    [string]$server_ip = $api_ip,
    [string]$agent_name = $env:computername,
	[string]$ossec_path = $env:SystemDrive+"\ossec-agent\",
	[string]$ossec_exe = "",
	[Int]$prompt_agent_name = 0,
	[switch]$help
	
	)

if(($help.isPresent)) {
	"Wazuh Add OSSEC Agent Windows
Github repository: http://github.com/wazuh/ossec-wazuh
API Documentation: http://documentation.wazuh.com/en/latest/ossec_api.html
Site: http://www.wazuh.com"
""
""
	"Usage: add_agent.ps1 -api_ip IP -username USERNAME -password PASSWORD"
	"Arguments description:
	Mandatory:
		-api_ip Wazuh API IP
		-username Wazuh API auth https username
		-password Wazuh API auth https password
        -ossec_exe OSSEC Agent installer full path [Default ossec-win32-agent.exe]
	Optionals:
		-api_port Wazuh API port [Default 55000]
		-server_ip OSSEC Manager IP [Default -api_ip]
		-agent_name OSSEC Agent Name [Default windows hostname]
		-ossec_path OSSEC Agent installation path [Default Sysdrive:\ossec-agent]
		-prompt_agent_name [0/1] In case agent name already exists on OSSEC Manager, prompt to ask Agent Name [default 0]
		-help Display help
	"
	Exit
}	


# Opening powershell as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { 
       "This script requires Administrator privileges"
	   Write-Host "Press any key to continue ..."
	   $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	   Exit
}

# Checking Administrator privilegies
function Test-Admin {
  $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if ((Test-Admin) -eq $false)  {
       "This script requires Administrator privileges"
	   Write-Host "Press any key to continue ..."
	   $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	   Exit
}

if($api_ip -eq ""){
	"-api_ip is required. Try help to display arguments list"
	Write-Host "Press any key to continue ..."
	$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	Exit
}
if($username -eq ""){
	"-username is required. Try -help to display arguments list"
	Write-Host "Press any key to continue ..."
	$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")	
	Exit
}
if($password -eq ""){
	"-password is required. Try -help to display arguments list"
	Write-Host "Press any key to continue ..."
	$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")	
	Exit
}
if($ossec_exe -eq ""){
	"-ossec_exe is required. Try -help to display arguments list"
	Write-Host "Press any key to continue ..."
	$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")	
	Exit
}

# Create Log file
# ps1
$path = "."

$file_log = "\add_agent.log"

# Ossec service name
$ossec_service = 'OssecSvc'

#Agent installer path and name
$exe = $ossec_exe

if(!(Test-Path -Path $path$file_log)){
	New-Item -Path $path$file_log -ItemType File
}else{
    Clear-Content $path$file_log
	Add-Content -Path $path$file_log -Value "Starting"
	"Starting"
}

#################
# Aux functions
#################
function AgentName
{
    $read_agent_name = ""
    while(!($read_agent_name -match "^[A-Za-z0-9\\-_]+$") -Or !($read_agent_name.length -gt 2 -And $read_agent_name.length -lt 33)){
        $read_agent_name = Read-Host 'Enter OSSEC Agent name (Name must contain only alphanumeric characters min=2 max=32)'
    }
    $read_agent_name
}

Add-Content -Path $path$file_log -Value "Privileges OK"

# If OSSEC service already exits, do not install.
Get-Service -Name $ossec_service -ErrorAction SilentlyContinue | Restart-Service -ErrorAction SilentlyContinue
if ($? -eq $true) {
	Add-Content -Path $path$file_log -Value "ERROR: OSSEC SERVICE already installed. Please uninstall OSSEC and run again."
	"ERROR: OSSEC SERVICE already installed."
    Exit
}

# Verifying executable path
if(!(Test-Path -Path $exe)){
	Add-Content -Path $path$file_log -Value "OSSEC Executable does not exists: $exe"
	"OSSEC Executable does not exists: $exe"
    Exit
}

# Certs functions
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    
    public class PolicyCert : ICertificatePolicy {
        public PolicyCert() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate cert,
            WebRequest wRequest, int certProb) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = new-object PolicyCert 
Add-Content -Path $path$file_log -Value "Certify OK"
"Certify OK"
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))

############################
# Aux functions
############################

function setConnection($User,$Password){
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    $webclient = new-object system.net.webclient;
    $PWord = ConvertTo-SecureString –String $Password –AsPlainText -Force
    $Credential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $User, $PWord;
    $webclient.Credentials = $Credential;
    return $webclient
}
function addAgent($webclient, $api_ip, $api_port, $agent_name, $prompt_agent_name, $path, $file_log){

    $addedOK = 0
    $ID = "-1"
    while($addedOK -eq 0){
        $url = "https://" + $api_ip + ":" + $api_port;
        $resource = $url + "/agents/add/" + $agent_name
        try{
            $response = $webclient.DownloadString($resource);
            $response = ConvertFrom-Json20($response)
        }catch{
            $exceptionDetails = $_.Exception
            Add-Content -Path $path$file_log -Value "$($exceptionDetails)"
            Write-Host $exceptionDetails.Message
            exit 1001
        }
        if($response.error -eq 0){
            $ID = $response.response.id
            $addedOK = 1
        }else{
            Add-Content -Path $path$file_log -Value "$($response.description)"
            if($prompt_agent_name){
                Write-Host $response.description
                $agent_name = AgentName
            }else{
                Write-Host $response.description
                exit 1001
            }
        }
    }
    return $ID

}

function getKey($webclient, $api_ip, $api_port, $agent_id, $path, $file_log ){

    $key = "-1"
    $url = "https://" + $api_ip + ":" + $api_port;
	$resource = $url + "/agents/"+$ID+"/key"
	try{
        $response = $webclient.DownloadString($resource);
        $response = ConvertFrom-Json20($response)
	}catch{
		$exceptionDetails = $_.Exception
		Add-Content -Path $path$file_log -Value "$($exceptionDetails)"
		Write-Host $exceptionDetails.Message
		exit 1001
	}
	if($response.error -eq 0){
		$key = $response.response.key
	}else{
		Add-Content -Path $path$file_log -Value "$($response.description)"
		Write-Host $response.description
		exit 1001
	}
    return $key
}

function importKey($key, $ossec_path, $path, $file_log ){
    $psi = New-Object System.Diagnostics.ProcessStartInfo;
    $psi.FileName = $ossec_path+"manage_agents.exe"; #process file_log
    #Verifying manage_agent path
    if(!(Test-Path -Path $psi.FileName)){
        Add-Content -Path $path$file_log -Value $psi.FileName" does not exists"
		Write-Host $psi.FileName" does not exists"
        Exit
    }
    $psi.UseShellExecute = $false; #start the process from it's own executable file
    $psi.RedirectStandardInput = $true; #enable the process to read from standard input
    $psi.Arguments = "-i " + $key
    $p = [System.Diagnostics.Process]::Start($psi);
    Start-Sleep -s 2 #wait 2 seconds so that the process can be up and running
    $p.StandardInput.WriteLine("y");
    Start-Sleep -s 2 #wait 2 seconds so that the process can be up and running
    $p.StandardInput.WriteLine("ENTER");
	Add-Content -Path $path$file_log -Value "Import Key into OSSEC OK"
    Write-Host "Import Key into OSSEC OK"
	# Start OSSEC Service
	net start OssecSvc
	Add-Content -Path $path$file_log -Value "OSSEC SERVICE OK"
    Write-Host "OSSEC SERVICE OK"
    # Restart Service
    Start-Sleep -s 3 #wait 5s and restart OSSEC Agent (Better way to send a notification to OSSEC Manager)
    Get-Service -Name $ossec_service -ErrorAction SilentlyContinue | Restart-Service -ErrorAction SilentlyContinue
	Start-Sleep -s 3 #wait 5s and restart OSSEC Agent (Better way to send a notification to OSSEC Manager)
    Get-Service -Name $ossec_service -ErrorAction SilentlyContinue | Restart-Service -ErrorAction SilentlyContinue
    Write-Host "AGENT INSTALLED SUCCESSFULLY"
}

function ConvertFrom-Json20([object] $item){ 
    add-type -assembly system.web.extensions 
    $ps_js=new-object system.web.script.serialization.javascriptSerializer
    return $ps_js.DeserializeObject($item) 
}

############################
#Installing Agent Executable
############################
$AllArgs = @('/S /D='+$env:SystemDrive+'\ossec-agent\')
try{
    $check = Start-Process $exe $AllArgs -Wait -Verb runAs
}catch{
        "OSSEC Installation failed"
        Add-Content -Path $path$file_log -Value "OSSEC Executable does not exists: $exe"
        "OSSEC Executable does not exists: $exe"
        $exceptionDetails = $_.Exception
        Add-Content -Path $path$file_log -Value "$($exceptionDetails)"
		Write-Host $exceptionDetails.Message
        exit 1001
}

Add-Content -Path $path$file_log -Value "OSSEC Installed OK"
"OSSEC Installed OK"


############################
#Server ip to ossec.conf
############################
if((Test-Path -Path $ossec_path"ossec.conf")){
    if(!(select-string -Quiet -path $ossec_path"ossec.conf" -pattern '<server-ip>.*[^1.2.3.4].*</server-ip>')){
        Add-Content -Path $ossec_path"ossec.conf" -Value "<ossec_config><client><server-ip>$server_ip</server-ip></client></ossec_config>"
        Add-Content -Path $path$file_log -Value "Added server-ip to ossec.conf"
		"Added server-ip to ossec.conf"
    }
}else{
    Add-Content -Path $path$file_log -Value "ERROR: OSSEC conf not found at $ossec_path"+"ossec.conf"
	"ERROR: OSSEC conf not found at "+$ossec_path+"ossec.conf"
}

############################
# Prompt: Agent name
############################
if($prompt_agent_name){
    $agent_name = AgentName
}

####################
# API: Adding Agent
####################

$webclient = setConnection $username $password
$ID = addAgent $webclient $api_ip $api_port $agent_name $prompt_agent_name $path $file_log

##################
# API: Getting key
##################

if($ID -ne "-1"){
    Add-Content -Path $path$file_log -Value "Adding Agent OK"
    Write-Host "Adding Agent OK"
    $KEY = getKey $webclient $api_ip $api_port $ID $path $file_log
}else{
    Add-Content -Path $path$file_log -Value "Error registering agent, ID not valid, stop."
    Write-Host "Error registering agent, ID not valid, stop."
    exit 1001   
}

#################
# API: Import key
################# 

if($KEY -ne "-1"){
    Add-Content -Path $path$file_log -Value "Getting KEY OK"
    Write-Host "Getting KEY OK"
    importKey $KEY $ossec_path $path $file_log
}else{
    Add-Content -Path $path$file_log -Value "Error getting key, KEY not valid, stop."
    Write-Host "Error getting key, KEY not valid, stop."
    exit 1001  
}
