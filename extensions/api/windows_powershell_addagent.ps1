$resource = "http://192.168.73.143:8080/agents/add/134" + $env:computername
$resource
$response = Invoke-RestMethod -Method Get -Uri $resource
$ID = $response[0].ID
$ID

if ($ID) {
	$resource = "http://192.168.73.143:8080/agents/"+$ID+"/key"
	$resource
	$response = Invoke-RestMethod -Method Get -Uri $resource
	$key = $response[0].key
	$key
}
if($key) {
	$manageAgents = "C:\Program Files\ossec-agent\manage_agents.exe"
	Invoke-Expression "& `"$manageAgents`" -i `"$key`""
	#Write-Host "hello world
	#$psi = New-Object System.Diagnostics.ProcessStartInfo;
    #$psi.FileName = "C:\Program Files\ossec-agent\manage_agents.exe"; 
    #$psi.UseShellExecute = $false;
    #$psi.RedirectStandardInput = $true; 
    #$psi.RedirectStandardOutput = $true; 
    #$p = [System.Diagnostics.Process]::Start($psi);
    #Start-Sleep -s 2 
    #$p.StandardInput.WriteLine("y");
    #$p.StandardOutput.ReadToEnd();
}
net start OssecSvc
