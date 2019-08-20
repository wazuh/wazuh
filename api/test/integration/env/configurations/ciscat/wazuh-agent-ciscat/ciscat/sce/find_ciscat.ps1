$paths = Get-PSDrive -PSProvider "FileSystem" | ForEach-Object { Get-ChildItem -Path $_.Root -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "CIS-CAT.bat" } | Select-Object -First 1 FullName } | Select-Object -First 1
if ( $paths -eq $null ) {
    Exit $Env:XCCDF_RESULT_FAIL
}
Write-Output $paths.FullName
Exit $Env:XCCDF_RESULT_PASS