param([switch]$Elevated)

# Create Log file
$path = $PSScriptRoot
$file_log = "\ossec_deploy.txt"
$slash = "\"

# Ossec service name
$ossec_service = 'OssecSvc'

############################
#SETTINGS
############################

#API SETTINGS
$api_port = "55000"
$api_ip = ""
$username = ""
$password = ""

#OSSEC Manager server_ip
$server_ip = $api_ip

# AGENT NAME
$agent_name = $env:computername

# ASK FOR AGENT NAME
$prompt_agent_name = 1

# Installation Default Path (letter and patch must be the same where ossec agent is installed)
#$ossec_path = $env:SystemDrive"\Program Files\ossec-agent\"
$ossec_path = $env:SystemDrive+"\Program Files (x86)\ossec-agent\"

# Executable name
$exe = "ossec-win32-agent.exe"
$exe = $slash+$exe

if(!(Test-Path -Path $path$file_log)){
	New-Item -Path $path$file_log -ItemType File
}else{
    Clear-Content $path$file_log
	Add-Content -Path $path$file_log -Value "Starting"
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

# Opening powershell as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

# Checking Administrator privilegies
function Test-Admin {
  $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if ((Test-Admin) -eq $false)  {
	   Add-Content -Path $path$file_log -Value "`nERROR: Administrator privilegies failed"
       "This script requires Administrator privileges"
	   Write-Host "Press any key to continue ..."
	   $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	   Exit
}
Add-Content -Path $path$file_log -Value "Privileges OK"

# If OSSEC service already exits, do not install.
Get-Service -Name $ossec_service -ErrorAction SilentlyContinue | Restart-Service -ErrorAction SilentlyContinue
if ($? -eq $true) {
	Add-Content -Path $path$file_log -Value "ERROR: OSSEC SERVICE already installed."
    Exit
}

# Verifying executable path
if(!(Test-Path -Path $path$exe)){
	Add-Content -Path $path$file_log -Value "OSSEC Executable does not exists: $path$exe"
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
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))


############################
#Installing Agent Executable
############################
$AllArgs = @('/S')
$check = Start-Process $path$exe $AllArgs -Wait -Verb runAs
Add-Content -Path $path$file_log -Value "OSSEC Installed OK"

############################
#Server ip to ossec.conf
############################
if((Test-Path -Path $ossec_path"ossec.conf")){
    if(!(select-string -Quiet -path $ossec_path"ossec.conf" -pattern '<server-ip>.*[^1.2.3.4].*</server-ip>')){
        Add-Content -Path $ossec_path"ossec.conf" -Value "<ossec_config><client><server-ip>$server_ip</server-ip></client></ossec_config>"
        Add-Content -Path $path$file_log -Value "Added server-ip to ossec.conf"
    }
}else{
    Add-Content -Path $path$file_log -Value "ERROR: OSSEC conf not found at $ossec_path"+"ossec.conf"
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
$addedOK = 0
while($addedOK -eq 0){
    $url = "https://" + $api_ip + ":" + $api_port;
    $resource = $url + "/agents/add/" + $agent_name
    try{
        $response = Invoke-RestMethod -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get -Uri $resource
    }catch{
        $exceptionDetails = $_.Exception
        Add-Content -Path $path$file_log -Value "$($exceptionDetails)"
        exit 1001
    }
    if($response.error -eq 0){
        $ID = $response.response.ID
        $addedOK = 1
    }else{
        Add-Content -Path $path$file_log -Value "$($response.description)"
        if($prompt_agent_name){
            $response.description
            $agent_name = AgentName
        }else{
            exit 1001
        }
    }
}
Add-Content -Path $path$file_log -Value "Adding Agent OK"

##################
# API: Getting key
##################
if ($ID) {
	$resource = $url + "/agents/"+$ID+"/key"
	try{
		$response = Invoke-RestMethod -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get -Uri $resource
	}catch{
		$exceptionDetails = $_.Exception
		Add-Content -Path $path$file_log -Value "$($exceptionDetails)"
		exit 1001
	}
	if($response.error -eq 0){
		$key = $response.response.key
	}else{
		Add-Content -Path $path$file_log -Value "$($response.description)"
		exit 1001
	}
}
Add-Content -Path $path$file_log -Value "Getting KEY OK"
#################
# API: Import key
#################
if($key) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo;
    $psi.FileName = $ossec_path+"manage_agents.exe"; #process file_log
    #Verifying manage_agent path
    if(!(Test-Path -Path $psi.FileName)){
        Add-Content -Path $path$file_log -Value "$psi.FileName does not exists"
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
	Add-Content -Path $path$file_log -Value "Import Key OK"
	# Start OSSEC Service
	net start OssecSvc
	Add-Content -Path $path$file_log -Value "OSSEC SERVICE OK"
    # Restart Service
    Start-Sleep -s 5 #wait 5s and restart OSSEC Agent (Better way to send a notification to OSSEC Manager)
    Get-Service -Name $ossec_service -ErrorAction SilentlyContinue | Restart-Service -ErrorAction SilentlyContinue
}


