$ErrorActionPreference = "Continue"; $d = "C:\ebpfpoc"; $ebpf = "C:\Program Files\ebpf-for-windows"
"### ntosebpfext: trust test cert, install driver, export program info"
Import-Certificate -FilePath "$d\ntos\ntosebpfext.cer" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath "$d\ntos\ntosebpfext.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
Copy-Item "$d\ntos\ntosebpfext.sys" C:\Windows\System32\drivers\ -Force
Push-Location "$d\ntos"; & .\ntos_ebpf_ext_export_program_info.exe 2>&1; "export rc=$LASTEXITCODE"; Pop-Location
sc.exe create ntosebpfext type= kernel start= demand binPath= C:\Windows\System32\drivers\ntosebpfext.sys
sc.exe start ntosebpfext
"### load programs"
Push-Location $ebpf

netsh ebpf add program "$d\proc_watch.o" 2>&1
netsh ebpf add program "$d\bind_watch.o" 2>&1
netsh ebpf show programs 2>&1
Pop-Location
"### workload"
for ($i = 0; $i -lt 20; $i++) { & "$d\quick.exe" }
$l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Any, 0); $l.Start(); $lp = $l.LocalEndpoint.Port
$u = [Net.Sockets.UdpClient]::new(0); $up = $u.Client.LocalEndPoint.Port
"TRUTH runner_pid=$PID tcp_port=$lp udp_port=$up quick=20 exit=7"
Start-Sleep 1; $l.Stop(); $u.Close()
"### maps"
& "$ebpf\bpftool.exe" map show 2>&1
& "$ebpf\bpftool.exe" map dump name proc_exit 2>&1 | Select-Object -First 40
& "$ebpf\bpftool.exe" map dump name binds 2>&1 | Select-Object -First 40
"EBPF TEST DONE"
