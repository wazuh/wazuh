# Hotfix store (CBS) and browser-extension folder notifications.
$dir = 'C:\poc41434'; $log = "$dir\inv3.txt"; $truth = "$dir\truth_inv3.txt"
Remove-Item $log, $truth -ErrorAction SilentlyContinue
$prof = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default'
$created = -not (Test-Path $prof); New-Item -ItemType Directory -Force (Join-Path $prof 'Extensions') | Out-Null
if (-not (Test-Path "$prof\Preferences")) { '{}' | Out-File "$prof\Preferences" -Encoding ascii }
$p = Start-Process "$dir\invpoc.exe" -ArgumentList 400, "`"$prof`"" -RedirectStandardOutput $log -PassThru -WindowStyle Hidden
Start-Sleep 4
function T($what) { "$([DateTime]::UtcNow.ToFileTimeUtc()) $what" | Out-File $truth -Append -Encoding ascii }
"profile_created_for_test=$created"
T 'ext_add'; New-Item -ItemType Directory -Force "$prof\Extensions\pocext41434\1.0" | Out-Null; '{"name":"poc","version":"1.0","manifest_version":3}' | Out-File "$prof\Extensions\pocext41434\1.0\manifest.json" -Encoding ascii; Start-Sleep 3
T 'prefs_write'; (Get-Content "$prof\Preferences" -Raw) | Out-File "$prof\Preferences" -Encoding ascii -NoNewline; Start-Sleep 3
T 'ext_del'; Remove-Item "$prof\Extensions\pocext41434" -Recurse -Force; Start-Sleep 3
$hf0 = (Get-HotFix).Count
T 'feature_install Telnet-Client'; $r = Install-WindowsFeature Telnet-Client; T "feature_install_done success=$($r.Success)"; Start-Sleep 10
T 'feature_remove Telnet-Client'; $r = Uninstall-WindowsFeature Telnet-Client; T "feature_remove_done success=$($r.Success)"; Start-Sleep 10
"hotfix count before=$hf0 after=$((Get-HotFix).Count)"
Stop-Process -Id $p.Id -ErrorAction SilentlyContinue
"INV3 DONE"
