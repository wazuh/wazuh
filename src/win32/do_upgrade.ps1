# Check if there is an upgrade in progress
if (Test-Path ".\upgrade\upgrade_in_progress") {
    write-output "$(Get-Date -format u) - There is an upgrade in progress. Aborting..." >> .\upgrade\upgrade.log
    exit 1
}

write-output "0" | out-file ".\upgrade\upgrade_in_progress" -encoding ascii

# Delete previous upgrade.log
Remove-Item -Path ".\upgrade\upgrade.log" -ErrorAction SilentlyContinue

# Select powershell
if (Test-Path "$env:windir\sysnative") {
    write-output "$(Get-Date -format u) - Sysnative Powershell will be used to access the registry." >> .\upgrade\upgrade.log
    Set-Alias Start-NativePowerShell "$env:windir\sysnative\WindowsPowerShell\v1.0\powershell.exe"
} else {
    Set-Alias Start-NativePowerShell "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe"
}


function remove_upgrade_files {
    Remove-Item -Path ".\upgrade\*"  -Exclude "*.log", "upgrade_result" -ErrorAction SilentlyContinue
    Remove-Item -Path ".\wazuh-agent*.msi" -ErrorAction SilentlyContinue
    Remove-Item -Path ".\do_upgrade.ps1" -ErrorAction SilentlyContinue
}


function get_wazuh_installation_directory {
    Start-NativePowerShell {
        $path1 = "HKLM:\SOFTWARE\WOW6432Node\Wazuh, Inc.\Wazuh Agent"
        $key1 = "WazuhInstallDir"

        $path2 = "HKLM:\SOFTWARE\WOW6432Node\ossec"
        $key2 = "Install_Dir"

        $WazuhInstallDir = $null

        try {
            $WazuhInstallDir = (Get-ItemProperty -Path $path1 -ErrorAction SilentlyContinue).$key1
        }
        catch {
            $WazuhInstallDir = $null
        }

        if ($null -eq $WazuhInstallDir) {
            try {
                $WazuhInstallDir = (Get-ItemProperty -Path $path2 -ErrorAction SilentlyContinue).$key2
            }
            catch {
                $WazuhInstallDir = $null
            }
        }

        if ($null -eq $WazuhInstallDir) {
            Write-output "$(Get-Date -format u) - Couldn't find Wazuh in the registry. Upgrade will assume current path is correct" >> .\upgrade\upgrade.log
            $WazuhInstallDir = (Get-Location).Path.TrimEnd('\')
        }

        return $WazuhInstallDir
    }
}

# Check process status
function check-process
{
    $process_id = (Get-Process wazuh-agent).id
    $counter = 10
    while($process_id -eq $null -And $counter -gt 0)
    {
        $counter--
        Start-Service -Name "Wazuh"
        Start-Sleep 2
        $process_id = (Get-Process wazuh-agent).id
    }
    write-output "$(Get-Date -format u) - Process ID: $($process_id)." >> .\upgrade\upgrade.log
}

# Check new version and restart the Wazuh service
function check-installation
{
    $new_version = (Get-Content VERSION)
    $counter = 5
    while($new_version -eq $current_version -And $counter -gt 0)
    {
        write-output "$(Get-Date -format u) - Waiting for the Wazuh-Agent installation to end." >> .\upgrade\upgrade.log
        $counter--
        Start-Sleep 2
        $new_version = (Get-Content VERSION)
    }
    write-output "$(Get-Date -format u) - Restarting Wazuh-Agent service." >> .\upgrade\upgrade.log
    Get-Service -Name "Wazuh" | Start-Service
}

# Stop UI and launch the msi installer
function install
{
    kill -processname win32ui -ErrorAction SilentlyContinue -Force
    Remove-Item .\upgrade\upgrade_result -ErrorAction SilentlyContinue
    write-output "$(Get-Date -format u) - Starting upgrade process." >> .\upgrade\upgrade.log
    cmd /c start /wait (Get-Item ".\wazuh-agent*.msi").Name -quiet -norestart -log installer.log
}

# Check that the Wazuh installation runs on the expected path
$wazuhDir = get_wazuh_installation_directory
$normalizedWazuhDir = $wazuhDir.TrimEnd('\')
$currentDir = (Get-Location).Path.TrimEnd('\')

if ($normalizedWazuhDir -ne $currentDir) {
    Write-Output "$(Get-Date -format u) - Current working directory is not the Wazuh installation directory. Aborting." >> .\upgrade\upgrade.log
    Write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
    remove_upgrade_files
    exit 1
}

# Get current version
$current_version = (Get-Content VERSION)
write-output "$(Get-Date -format u) - Current version: $($current_version)." >> .\upgrade\upgrade.log

# Ensure no other instance of msiexec is running by stopping them
Get-Process msiexec | Stop-Process -ErrorAction SilentlyContinue -Force

# Install
install
check-installation

write-output "$(Get-Date -format u) - Installation finished." >> .\upgrade\upgrade.log

check-process

# Wait for agent state to be cleaned
Start-Sleep 10

# Check status file
function Get-AgentStatus {
    Select-String -Path '.\wazuh-agent.state' -Pattern "^status='(.+)'" | %{$_.Matches[0].Groups[1].value}
}

$status = Get-AgentStatus
$counter = 30
while($status -ne "connected"  -And $counter -gt 0)
{
    $counter--
    Start-Sleep 2
    $status = Get-AgentStatus
}
Write-Output "$(Get-Date -Format u) - Reading status file: status='$status'." >> .\upgrade\upgrade.log

If ($status -ne "connected")
{
    write-output "$(Get-Date -format u) - Upgrade failed." >> .\upgrade\upgrade.log
    write-output "2" | out-file ".\upgrade\upgrade_result" -encoding ascii
}
Else
{
    write-output "0" | out-file ".\upgrade\upgrade_result" -encoding ascii
    write-output "$(Get-Date -format u) - Upgrade finished successfully." >> .\upgrade\upgrade.log
    $new_version = (Get-Content VERSION)
    write-output "$(Get-Date -format u) - New version: $($new_version)." >> .\upgrade\upgrade.log
}

remove_upgrade_files

exit 0

# SIG # Begin signature block
# MIIohAYJKoZIhvcNAQcCoIIodTCCKHECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCByS9bTRQMQbvgw
# tEV0YjsW+FMAYLM0PsyMV1jK6TcrP6CCDfAwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggc4MIIFIKADAgECAhAOLFD3klR6AH0Z074B0zupMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjMwNjA4MDAwMDAwWhcNMjYwNjE3
# MjM1OTU5WjCBwDETMBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgEC
# EwhEZWxhd2FyZTEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEDAOBgNV
# BAUTBzU3MTQ1NDcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMREw
# DwYDVQQHEwhTYW4gSm9zZTETMBEGA1UEChMKV2F6dWgsIEluYzETMBEGA1UEAxMK
# V2F6dWgsIEluYzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANiEOX1+
# xF+AOWJJSrOzb3f75MOSaKwSEkc+JG3eSDZuH9azmaf4QZlaIBo+cM7TeK1c8pSF
# 2mMVxAhmjWuGJwmSCciwXpY2F5GDWg/fOsezvreooTIuc/uCzKaBfbf0dtANJIuU
# v1padrddTD6N8uqOLo7dGfUo8M1m969ii7NpkT45bjRrmQwSh8HP4/PL2CPjHHCF
# mTDaCBOU/bA9E81Xyo9MrY8wfwx64vcaGeL0qnNUGKU39t/uiVd+NLcTpYyi1FMo
# Z9bnS8vtIveTSpA8LVDtgIRM4QBKIad4A2RGdQwXERdnyMtPK18QEac9vXQZkUZW
# 520JMbhhUoBE6B5w8JxtH7gPryMLuE/18LIvS5n93R5z57fF53UERspBhco6crrH
# A4h+FEHfmaOBk5+Y/ya8NTO4EyWPvMcYd6qUxaPk3X2/0Kyu2xHpUNiH2kChm0+1
# RPzk4Ox4d8BNQoyUGw3dL1sS+nau6rDcC/weLTMjG1wL9JijAtqQ6GmBQQIDAQAB
# o4ICAjCCAf4wHwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHQYDVR0O
# BBYEFKqNNumVAk849bW/XS9dFZDsp931MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
# DDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZT
# SEEzODQyMDIxQ0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNB
# MS5jcmwwPQYDVR0gBDYwNDAyBgVngQwBAzApMCcGCCsGAQUFBwIBFhtodHRwOi8v
# d3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgZQGCCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWdu
# aW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQCMAAwDQYJKoZIhvcN
# AQELBQADggIBAK9374uEj8Jn4x9V1N5NHTFft7jXr55hFCxAu7BQE7z8OtUQ4YTe
# hzPI/PvrSgu4A0WCFCcmGfwcETXl6YZtq0uxXUfoMmh4XooelxK/yljEv+gcJrKA
# eVKLsz/P75Af7JoR4ywTaGjYJobyHenoOcBYDM5AX5fmG4Sr2F1FO8oBEy3ayebt
# YIwZxOM22uNqReEui7dYiN6bYTfTWUUhbIvJzHSMMO8rG+6W35J/W3RXIbTFYjl7
# CE54xVgmCXVIbW1wRdRd6ZhmkYXxHQlPE1x2VPCqKN4ddwWqevZi8fDOa5z+0b1p
# JWDL6O1AvKy7SXmRdEQ6IZnmSm3tvW74GMJhiE35GlvoxJxh0Lbf5nQ/M2UnoYlR
# yxB1736mkoiiHN4O1jb93kKxJeQLjKdlHKBLIny+ilYWCGddJiu6c1+JYPTC2Sxv
# j4QMuPygb7aPYnBjMd6E+Df3udBhKslJOiSlOePet3UHZ9slxa3qhuSBC+jfn+q5
# cofQkNBuUACgL6HBx1N0rfD7RBfJ2Nugce+1xEurhkh9ZjTHtcHMdwOFS/rGtcNO
# iQbpE2eeWhUTJVsr7fkxmNgvB1cgSF/OefD4T9nDnXqx/4AjaekQXSxkfg388dvj
# olzXCoC7SaXprPqkKjMWzYmcTdaivsBriz06712iEpEGLcGJ+3Ug7BnvMYIZ6jCC
# GeYCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# QTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQw
# OTYgU0hBMzg0IDIwMjEgQ0ExAhAOLFD3klR6AH0Z074B0zupMA0GCWCGSAFlAwQC
# AQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIE
# IAceWzLyKOl2jIZqKrgDuiGLaoa9Rq3Ad/d5vRonkXRgMA0GCSqGSIb3DQEBAQUA
# BIIBgG1cbj/qax/vi2HZEYl/DCO/NKDvCun9M7Isk3J4gl5bWncVdOHMaF63mMVJ
# y7dSZml0dltbjFegvg+nW+4mmhkqL9IjCxzNFJXBsCrjbU9nJ4XOVU8SrCrZDDl2
# S8dCwaAUrIz9IT4xJXDsv9oDamoSBqwtFlEvJJDJvQP9rI1pHGNz3pygxZ0t+Eg7
# nqYY8IYfKBmlq6MnE6CWxS5QM6O1rMgMoDYiucjhKgVOD0lV0l8mFvkuIKf2e6v1
# weVoUWEiQEY0vBIKZtKHq+9aFGaYlNs4tXr7FiiK3P4rIGXMIAjpyu1D3bp5qNYF
# SkEv9P+YDIsvBCRDjX26zAwcD7dKaw8+TdSqHtsLNzVb/Ph9utKsz3fyATsx63U2
# LyEu2VSDBCGqNsR5f8vsB39lvVJIFn7H5/52349dWTrMwR+u6QhS8HZiaukSCisd
# ENc1EHRE4Qr6cf1rs9xzZWi35Uppv7u7waKfuiCHHnJxDN3mXbcw9wYj3Y2Iocnu
# HouYTqGCF0Awghc8BgorBgEEAYI3AwMBMYIXLDCCFygGCSqGSIb3DQEHAqCCFxkw
# ghcVAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEG
# CWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCBY5o8o+UQGTx9gX+9hc7sPUodc
# ELunbKogxEM2/J/DZwIRAIcLopvGi4keMjbEKTQCYisYDzIwMjQwNzMwMTgyNTU1
# WqCCEwkwggbCMIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f5WEWMA0GCSqGSIb3DQEB
# CwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgQ0EwHhcNMjMwNzE0MDAwMDAwWhcNMzQxMDEzMjM1OTU5WjBIMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xIDAeBgNVBAMTF0RpZ2lD
# ZXJ0IFRpbWVzdGFtcCAyMDIzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEAo1NFhx2DjlusPlSzI+DPn9fl0uddoQ4J3C9Io5d6OyqcZ9xiFVjBqZMRp82q
# smrdECmKHmJjadNYnDVxvzqX65RQjxwg6seaOy+WZuNp52n+W8PWKyAcwZeUtKVQ
# gfLPywemMGjKg0La/H8JJJSkghraarrYO8pd3hkYhftF6g1hbJ3+cV7EBpo88MUu
# eQ8bZlLjyNY+X9pD04T10Mf2SC1eRXWWdf7dEKEbg8G45lKVtUfXeCk5a+B4WZfj
# RCtK1ZXO7wgX6oJkTf8j48qG7rSkIWRw69XloNpjsy7pBe6q9iT1HbybHLK3X9/w
# 7nZ9MZllR1WdSiQvrCuXvp/k/XtzPjLuUjT71Lvr1KAsNJvj3m5kGQc3AZEPHLVR
# zapMZoOIaGK7vEEbeBlt5NkP4FhB+9ixLOFRr7StFQYU6mIIE9NpHnxkTZ0P387R
# Xoyqq1AVybPKvNfEO2hEo6U7Qv1zfe7dCv95NBB+plwKWEwAPoVpdceDZNZ1zY8S
# dlalJPrXxGshuugfNJgvOuprAbD3+yqG7HtSOKmYCaFxsmxxrz64b5bV4RAT/mFH
# Coz+8LbH1cfebCTwv0KCyqBxPZySkwS0aXAnDU+3tTbRyV8IpHCj7ArxES5k4Msi
# K8rxKBMhSVF+BmbTO77665E42FEHypS34lCh8zrTioPLQHsCAwEAAaOCAYswggGH
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSME
# GDAWgBS6FtltTYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUpbbvE+fvzdBkodVW
# qWUxo97V40kwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NB
# LmNybDCBkAYIKwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGlu
# Z0NBLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAgRrW3qCptZgXvHCNT4o8aJzYJf/L
# LOTN6l0ikuyMIgKpuM+AqNnn48XtJoKKcS8Y3U623mzX4WCcK+3tPUiOuGu6fF29
# wmE3aEl3o+uQqhLXJ4Xzjh6S2sJAOJ9dyKAuJXglnSoFeoQpmLZXeY/bJlYrsPOn
# vTcM2Jh2T1a5UsK2nTipgedtQVyMadG5K8TGe8+c+njikxp2oml101DkRBK+IA2e
# qUTQ+OVJdwhaIcW0z5iVGlS6ubzBaRm6zxbygzc0brBBJt3eWpdPM43UjXd9dUWh
# pVgmagNF3tlQtVCMr1a9TMXhRsUo063nQwBw3syYnhmJA+rUkTfvTVLzyWAhxFZH
# 7doRS4wyw4jmWOK22z75X7BC1o/jF5HRqsBV44a/rCcsQdCaM0qoNtS5cpZ+l3k4
# SF/Kwtw9Mt911jZnWon49qfH5U81PAC9vpwqbHkB3NpE5jreODsHXjlY9HxzMVWg
# gBHLFAx+rrz+pOt5Zapo1iLKO+uagjVXKBbLafIymrLS2Dq4sUaGa7oX/cR3bBVs
# rquvczroSUa31X/MtjjA2Owc9bahuEMs305MfR5ocMB3CtQC4Fxguyj/OOVSWtas
# FyIjTvTs0xf7UGv/B3cfcZdEQcm4RtNsMnxYL2dHZeUbc7aZ+WssBkbvQR7w8F/g
# 29mtkIBEr4AQQYowggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIF
# jTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3Qg
# Q0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJV
# UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
# Y29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3y
# ithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1If
# xp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDV
# ySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiO
# DCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQ
# jdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/
# CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCi
# EhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADM
# fRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QY
# uKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXK
# chYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t
# 9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6ch
# nfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0
# MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqG
# SIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi
# +IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n0
# 96wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ8
# 7PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9v
# ytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQt
# J37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDdjCCA3ICAQEwdzBjMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRp
# Z2lDZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENB
# AhAFRK/zlJ0IOaa/2z9f5WEWMA0GCWCGSAFlAwQCAQUAoIHRMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjQwNzMwMTgyNTU1WjAr
# BgsqhkiG9w0BCRACDDEcMBowGDAWBBRm8CsywsLJD4JdzqqKycZPGZzPQDAvBgkq
# hkiG9w0BCQQxIgQgggq+c/FhfNaK7jGBZJmnB9Bo9FHcovpM/Y0ca8k03pwwNwYL
# KoZIhvcNAQkQAi8xKDAmMCQwIgQg0vbkbe10IszR1EBXaEE2b4KK2lWarjMWr00a
# mtQMeCgwDQYJKoZIhvcNAQEBBQAEggIASiJSvUXYPv33x6sEquCBM74QRlbRLNqR
# pGz9uAa78NRGA6nkLsvGy6rktGCgPFWii4Uyt9ImIvhW9MDRseRWJNi1kwl7arAa
# +zjTjc8kmVYQ5ObSy4xICJSJHXnqkF5rDjb5wnIBPdcfoYoeEfpuLl0rD+76duBH
# XfZJDAuhEOATwK6mBlm05uREl2RR8gw1WgUWVKxiXnqJ+F0ltSaYeOqBzIR3kK9M
# ReDRLxYX7ukj6CvSgbIZm+vxwW+SRbVKrzPDFEnzHS4MfJbQlGvdatcsbva/3fIL
# E+yKBk87aZ4jbzp1BpB1FvAu/76aOTMgFQosNO+81t3nxYPBZbj4xGm8ufWFTDRD
# mxDvM+KVsprG3CHzgxT/XjS2q55H1I5rfbf3pnD4VjW+485VAXhpyXQgtHz71KZa
# RXgj1y/eRpbtZGjPzdGh0wQ44xDFRTzqDeT9jbEi0myaZkqi5h0z0t0DljmYq3bq
# GF1MONl5QbJ2vOWulQLuoBhM4ko163Vkz4XlmKOlJ37jiuMrJDR0XXh8ptvD0VC0
# vazo9Aaon6c53gh0YOl+hNXl5RP/3I7DjEzCcsLwv5joSXN53oPad/w9+6lghIUZ
# VO/f5WWplCWdXFwXTIkPsU4Y7hHovHxsdGbpqao2fnk9lrWDLhhGK7fQD8j656px
# 7XYAzk2oth0=
# SIG # End signature block
