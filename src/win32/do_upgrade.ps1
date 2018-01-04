function backup
{
    New-Item -ItemType directory -Path .\backup -ErrorAction SilentlyContinue
    New-Item -ItemType directory -Path $env:temp\backup -ErrorAction SilentlyContinue
    Copy-Item .\* $env:temp\backup -force
    Remove-Item $env:temp\backup\backup -recurse -ErrorAction SilentlyContinue
    Copy-Item $env:temp\backup\* .\backup -force
}

function install
{
    kill -processname win32ui -ErrorAction SilentlyContinue -Force
    Remove-Item .\upgrade\upgrade_result -ErrorAction SilentlyContinue
    Start-Process -FilePath (Get-ChildItem ".\upgrade\wazuh-agent*.exe") -ArgumentList '/S'
}

function restore
{
    Copy-Item .\backup\* .\ -force
}


# Get current version
$current_version = (Get-Content VERSION.txt).split(" ")[1] -replace "^."
$current_file_date = (Get-Item ".\ossec-agent.exe").LastWriteTime
write-output "$(Get-Date -format u) - Current version: $($current_version)" > .\upgrade\upgrade.log

# Generating backup
write-output "$(Get-Date -format u) - Generating backup." >> .\upgrade\upgrade.log
backup

# Install
write-output "$(Get-Date -format u) - Installing" >> .\upgrade\upgrade.log
install

# Wait for installation completion
Start-Sleep 5
$new_file_date = (Get-Item ".\ossec-agent.exe").LastWriteTime
$counter = 5
while($current_file_date -ne $new_file_date -And $counter -gt 0)
{
    $counter--
    Start-Sleep 2
    $new_file_date = (Get-Item ".\ossec-agent.exe").LastWriteTime
}
write-output "$(Get-Date -format u) - Installation finished." >> .\upgrade\upgrade.log

# Check process status
$process_id = (Get-Process ossec-agent -ErrorAction SilentlyContinue).id
$counter = 5
while($process_id -eq $null -And $counter -gt 0)
{
    $counter--
    Start-Service -Name "Wazuh" -ErrorAction SilentlyContinue
    Start-Sleep 2
    $process_id = (Get-Process ossec-agent -ErrorAction SilentlyContinue).id
}
write-output "$(Get-Date -format u) - Process ID: $($process_id)" >> .\upgrade\upgrade.log

# Check status file
$status = Get-Content .\ossec-agent.state | select-string "status='connected'" -SimpleMatch
$counter = 5
while($status -eq $null -And $counter -gt 0)
{
    $counter--
    Start-Sleep 2
    $status = Get-Content .\ossec-agent.state | select-string "status='connected'" -SimpleMatch
}
write-output "$(Get-Date -format u) - Reading status file: $($status)" >> .\upgrade\upgrade.log

If ($status -eq $null)
{
    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
    restore
    write-output "$(Get-Date -format u) - Upgrade failed: Restoring." >> .\upgrade\upgrade.log
    .\ossec-agent.exe install-service >> .\upgrade\upgrade.log
    Start-Service -Name "ossec-agent" -ErrorAction SilentlyContinue
}
Else
{
    write-output "0" | out-file ".\upgrade\upgrade_result" -encoding ascii
    write-output "$(Get-Date -format u) - Upgrade finished successfully." >> .\upgrade\upgrade.log
    $new_version = (Get-Content VERSION.txt).split(" ")[1] -replace "^."
    write-output "$(Get-Date -format u) - New version: $($new_version)" >> .\upgrade\upgrade.log
}
