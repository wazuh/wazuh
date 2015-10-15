param([switch]$Elevated)

# Create Log file
$path = $PSScriptRoot
$file_log = "\ossec_deploy.txt"

if(!(Test-Path -Path $path$file_log)){
	New-Item -Path $path$file_log -ItemType File
}else{
	Add-Content -Path $path$file_log -Value "Starting"
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
#API SETTINGS
$api_port = "8080"
$api_ip = "192.168.73.145"
$username = "foo"
$password = "bar"
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))

#Installing Agent Executable
$exe = "C:\Users\snaow\Desktop\ossec-agent-win32-2.8.exe"
$AllArgs = @('/S')
$check = Start-Process $exe $AllArgs -Wait -Verb runAs
Add-Content -Path $path$file_log -Value "OSSEC Installed OK"
# Temp adding ip to ossec.conf
# $ossec_server_ip = "<ossec_config><client> <server-ip>192.168.73.145</server-ip> </client></ossec_config>"
# Add-Content "C:\Program Files\ossec-agent\ossec.conf" $ossec_server_ip

# API: Add Agent +  Get Key
$url = "https://" + $api_ip + ":" + $api_port;
$resource = $url + "/agents/add/" + $env:computername
try{
	$response = Invoke-RestMethod -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get -Uri $resource
}catch{
	$exceptionDetails = $_.Exception
	Add-Content -Path $path$file_log -Value "$($exceptionDetails)"
	exit 1001
}
if($response.error -eq 0){
	$ID = $response.response.ID
}else{
	Add-Content -Path $path$file_log -Value "$($response.description)"
	exit 1001
}
Add-Content -Path $path$file_log -Value "Adding Agent OK"
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
# API: Import key
if($key) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo;
    $psi.FileName = "C:\Program Files\ossec-agent\manage_agents.exe"; #process file
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
}


