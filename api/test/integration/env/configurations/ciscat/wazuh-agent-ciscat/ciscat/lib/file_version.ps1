function Get-FileVersion([string]$path, [string]$windows_view) {
    Write-Output $path
    
    $os64 = [System.Environment]::Is64BitOperatingSystem
    $pr64 = [System.Environment]::Is64BitProcess
    
    $massaged_path = $path
    if (($os64 -and !$pr64) -and $windows_view -eq "64_bit") {
        $massaged_path = $path -replace "C:\\[Ww]indows\\[Ss]ystem32", "C:\Windows\sysnative"
    }

    Write-Output "--------------------------------------------------"
    Write-Output "filepath=$($path)"

    Try {
        #$stuff = Get-Item $massaged_path

        $version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($massaged_path) | Select-Object FullName, FileVersionRaw, ProductVersionRaw, FileVersion, ProductVersion

        Write-Output "existence=true"
        Write-Output "file_version=$($version.FileVersion)"
        Write-Output "file_version_raw=$($version.FileVersionRaw)"
        Write-Output "product_version=$($version.ProductVersion)"
        Write-Output "product_version_raw=$($version.ProductVersionRaw)"
    }
    Catch [System.IO.FileNotFoundException] {
        Write-Output "existence=false"
    }

#    $stuff = Get-Item $massaged_path | Select-Object FullName, DirectoryName, Name, Length
    

#    $r = New-Object PSObject -Property @{
#	    "filepath"   = $path
#        "version" = $version.FileVersionRaw
#        "product_version" = $version.ProductVersionRaw
#        "version_info_version" = $version.FileVersion
#        "version_info_product_version" = $version.ProductVersion
#    }
#    $r
}

#Get-FileVersion("C:\Windows\System32\win32k.sys")
#Get-FileVersion "C:\Windows\System32\drivers\srv.sys" "32_bit"
#Get-FileVersion "C:\Windows\System32\drivers\srv.sys" "64_bit"
#Get-FileVersion("C:\Windows\System32\shell32.dll")
#Get-FileVersion("C:\Windows\System32\Chakra.dll")