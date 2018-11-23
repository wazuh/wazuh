# Check PowerShell version
if (((Test-Path variable:PSVersionTable) -eq $False) -Or ($PSVersionTable.PSVersion.Major -lt 4))
{
    Write-Host "You need PowerShell v4.0 or greater to run this script."
    Write-Host "Please refer to:"
    Write-Host "https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-windows-powershell?#upgrading-existing-windows-powershell"
    exit
}

# Get absolute path from relative path
function Resolve-FullPath
{
    [cmdletbinding()]
    param
    (
        [Parameter(
            Mandatory=$true,
            Position=0,
            ValueFromPipeline=$true)]
        [string] $path
    )
    
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
}

# Create destination directory recursively
function createDestDir
{
    [cmdletbinding()]
    param
    (
        [Parameter(
            Mandatory=$true,
            Position=0,
            ValueFromPipeline=$true)]
        [string] $fullPath
    )
    
    $test = (Test-Path -Path "$fullPath")
    if ($test -eq $False)
    {
        New-Item -ItemType Directory -Path "$fullPath" -ErrorAction SilentlyContinue | Out-Null
        $test = (Test-Path -Path "$fullPath")
        if ($test -eq $False)
        {
            Write-Host "Error creating path: `"$fullPath`"."
            exit
        }
    }
}

# Download file from a GitHub release
function getFileFromGitHubRelease
{
    [cmdletbinding()]
    param
    (
        [Parameter(
            Mandatory=$true,
            Position=0,
            ValueFromPipeline=$true)]
        [string] $repository,
        [Parameter(
            Mandatory=$true,
            Position=1,
            ValueFromPipeline=$true)]
        [string] $fileToGet,
        [Parameter(
            Mandatory=$true,
            Position=2,
            ValueFromPipeline=$true)]
        [string] $destDir
    )
    
    Write-Host "Determining latest release for `"$repository`"..."
    
    $releases = "https://api.github.com/repos/$repository/releases"
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $tag = (Invoke-WebRequest -Uri $releases -UseBasicParsing | ConvertFrom-Json)[0].tag_name
    
    Write-Host "Downloading file `"$fileToGet`" from latest release `"$tag`"..."
    
    $download = "https://raw.githubusercontent.com/$repository/$tag/$fileToGet"
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest $download -Out "$destDir\$fileToGet"
    
    Write-Host "File `"$fileToGet`" downloaded to `"$destDir\$fileToGet`"."
}

# Download file to a specific path
function downloadFile
{
    [cmdletbinding()]
    param
    (
        [Parameter(
            Mandatory=$true,
            Position=0,
            ValueFromPipeline=$true)]
        [string] $fileUrl,
        [Parameter(
            Mandatory=$true,
            Position=1,
            ValueFromPipeline=$true)]
        [string] $destPath
    )
    
    Write-Host "Downloading `"$fileUrl`"..."
    
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest $fileUrl -Out "$destPath"
    
    Write-Host "File downloaded to `"$destPath`"."
}

# Set destination directory prefix
$dir_prefix = "..\include"

# Convert relative path to absolute path
$dir_prefix = Resolve-FullPath($dir_prefix)

# libcJSON variables
$cjson_repo = "DaveGamble/cJSON"
$cjson_dir = "$dir_prefix\external\cJSON"

# dirent.h variables
$dirent_url = "https://raw.githubusercontent.com/tronkko/dirent/master/include/dirent.h"
$dirent_path = "$dir_prefix\dirent.h"

#unistd.h variables
$unistd_url = "https://gist.githubusercontent.com/mbikovitsky/39224cf521bfea7eabe9/raw/69e4852c06452a368a174ca1f0f33ce87bb52985/unistd.h"
$unistd_path = "$dir_prefix\unistd.h"

# Create directories if necessary
createDestDir($cjson_dir)

# Check if the necessary files are already available

$cjson_c = (Test-Path -Path "$cjson_dir\cJSON.c" -PathType Leaf)
if ($cjson_c -eq $False)
{
    # Download cJSON.c
    Write-Host "File `"cJSON.c`" not available."
    getFileFromGitHubRelease $cjson_repo "cJSON.c" "$cjson_dir"
} else {
    Write-Host "File `"cJSON.c`" already available."
}

$cjson_h = (Test-Path -Path "$cjson_dir\cJSON.h" -PathType Leaf)
if ($cjson_h -eq $False)
{
    # Download cJSON.h
    Write-Host "File `"cJSON.h`" not available."
    getFileFromGitHubRelease $cjson_repo "cJSON.h" "$cjson_dir"
} else {
    Write-Host "File `"cJSON.h`" already available."
}

$dirent_h = (Test-Path -Path "$dirent_path" -PathType Leaf)
if ($dirent_h -eq $False)
{
    # Download dirent.h
    Write-Host "File `"dirent.h`" not available."
    downloadFile $dirent_url "$dirent_path"
} else {
    Write-Host "File `"dirent.h`" already available."
}

$unistd_h = (Test-Path -Path "$unistd_path" -PathType Leaf)
if ($unistd_h -eq $False)
{
    # Download unistd.h
    Write-Host "File `"unistd.h`" not available."
    downloadFile $unistd_url "$unistd_path"
} else {
    Write-Host "File `"unistd.h`" already available."
}
