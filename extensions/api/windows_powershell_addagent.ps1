param([switch]$Elevated)
# Opening powershell as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

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
	  
#Installing Agent Executable
$exe = "C:\Users\snaow\Desktop\ossec-agent-win32-2.8.exe"
$AllArgs = @('/S')
$check = Start-Process $exe $AllArgs -Wait -Verb runAs
"OSSEC Installed"
# API: Add Agent +  Get Key
$url = "http://192.168.73.145:8080"
$resource = $url + "/agents/add/" + $env:computername
$response = Invoke-RestMethod -Method Get -Uri $resource
$ID = $response[0].ID
$ID
if ($ID) {
	$resource = $url + "/agents/"+$ID+"/key"
	$resource
	$response = Invoke-RestMethod -Method Get -Uri $resource
	$key = $response[0].key
	$key
}
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
}
# Start OSSEC Service
net start OssecSvc
