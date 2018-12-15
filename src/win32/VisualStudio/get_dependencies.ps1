# Check PowerShell version
if (((Test-Path variable:PSVersionTable) -eq $False) -Or ($PSVersionTable.PSVersion.Major -lt 4))
{
    Write-Host "You need PowerShell v4.0 or greater to run this script."
    Write-Host "Please refer to:"
    Write-Host "https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-windows-powershell?#upgrading-existing-windows-powershell"
    exit
}

# Check .NET Framework version
[int]$net_version = ((Get-ItemProperty "HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release)
[int]$net_45 = 378389
if ($net_version -lt $net_45)
{
    Write-Host "You need .NET Framework v4.5 or greater to run this script."
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
    
    # Use another user agent to properly follow URL redirections
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest $fileUrl -Out "$destPath" -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
    
    Write-Host "File downloaded to `"$destPath`"."
}

# Extract compressed archives
function Extract-CompressedFile
{
    [cmdletbinding()]
    param
    (
        [Parameter(
            Mandatory=$true,
            Position=0,
            ValueFromPipeline=$true)]
        [string] $srcFile,
        [Parameter(
            Mandatory=$true,
            Position=1,
            ValueFromPipeline=$true)]
        [string] $dstPath
    )

    if (-not (Get-Package -Name 'SharpCompress' -ErrorAction SilentlyContinue))
    {
        if (Find-Package -Name 'SharpCompress' -ErrorAction SilentlyContinue)
        {
            Find-Package -Name 'SharpCompress' | Install-Package -RequiredVersion '0.22.0' -Force -Scope CurrentUser 2>&1>$null
        } else {
            if (-not (Get-PackageSource -Name 'nuGet.org v2' -ErrorAction SilentlyContinue))
            {
                Register-PackageSource -Name 'nuGet.org v2' -ProviderName NuGet -Location "https://www.nuget.org/api/v2/" -Force 2>&1>$null
            }
            
            if (Find-Package -Name 'SharpCompress' -Source 'nuGet.org v2' -ErrorAction SilentlyContinue)
            {
                Find-Package -Name 'SharpCompress' -Source 'nuGet.org v2' | Install-Package -RequiredVersion '0.22.0' -Force -Scope CurrentUser 2>&1>$null
            }
        }
    }
    
    $pkg = (Get-Package -Name 'SharpCompress')
    $packageLocation = $pkg.Source
    $folder = $packageLocation.Substring(0,$packageLocation.LastIndexOf('\')) + '\lib\net45\'
    $dll = (Get-ChildItem -Path $folder -recurse -Include *.dll | Sort-Object -Descending | Select-Object -First 1)
    Add-Type -Path $dll.FullName
    
    $filestream = [System.IO.File]::OpenRead($srcFile)
    
    $reader = [SharpCompress.Readers.ReaderFactory]::Open($filestream)
    
    While ($reader.MoveToNextEntry())
    {
        if ($reader.Entry.IsDirectory)
        {
            $folder = $reader.Entry.Key
            $destDir = (Join-Path -Path $dstPath -ChildPath $folder)
            if (-NOT (Test-Path -Path $destDir))
            {
                $null = (New-Item -Path $destDir -ItemType Directory -Force)
            }
        } else {
            $file = $reader.Entry.Key
            $filepath = (Join-Path -Path $dstPath -ChildPath $file)
            if (Test-Path -Path $filepath)
            {
                Remove-Item -Path $filepath -Force
            }
            $CreateNew = [System.IO.FileMode]::CreateNew
            $fs = [System.IO.File]::Open($filepath, $CreateNew)
            $reader.WriteEntryTo($fs)
            $fs.close()
        }
    }
    
    $filestream.Close()
}

# Set destination directory prefix
$dir_prefix = ".."

# Convert relative path to absolute path
$dir_prefix = (Resolve-FullPath "$dir_prefix")

# dirent.h variables
$dirent_url = "https://raw.githubusercontent.com/tronkko/dirent/master/include/dirent.h"
$dirent_path = "$dir_prefix\include\dirent.h"

# unistd.h variables
$unistd_url = "https://gist.githubusercontent.com/mbikovitsky/39224cf521bfea7eabe9/raw/69e4852c06452a368a174ca1f0f33ce87bb52985/unistd.h"
$unistd_path = "$dir_prefix\include\unistd.h"

# getopt.h variables
$getopt_url = "https://raw.githubusercontent.com/pps83/libgetopt/master/getopt.h"
$getopt_path = "$dir_prefix\include\getopt.h"

# Create directories if necessary
createDestDir "$dirent_path"

# Check if the necessary files are already available

$dirent_h = (Test-Path -Path "$dirent_path" -PathType Leaf)
if ($dirent_h -eq $False)
{
    # Download dirent.h
    Write-Host "File `"$dirent_path`" not available."
    downloadFile $dirent_url "$dirent_path"
} else {
    Write-Host "File `"$dirent_path`" already available."
}

$unistd_h = (Test-Path -Path "$unistd_path" -PathType Leaf)
if ($unistd_h -eq $False)
{
    # Download unistd.h
    Write-Host "File `"$unistd_path`" not available."
    downloadFile $unistd_url "$unistd_path"
} else {
    Write-Host "File `"$unistd_path`" already available."
}

$getopt_h = (Test-Path -Path "$getopt_path" -PathType Leaf)
if ($getopt_h -eq $False)
{
    # Download unistd.h
    Write-Host "File `"$getopt_path`" not available."
    downloadFile $getopt_url "$getopt_path"
} else {
    Write-Host "File `"$getopt_path`" already available."
}

# Get external libraries

# Update directory prefix
$dir_prefix = "..\..\.."

# Convert relative path to absolute path
$dir_prefix = (Resolve-FullPath "$dir_prefix")

# Convert SQL schemas to C code
$schemas_dir = "$dir_prefix\wazuh_db"
$schemas_wildcard = "$schemas_dir\schema_*.sql"
$schemas_outdir = "$dir_prefix\win32\VisualStudio\include"

$schemas = @(Get-ChildItem -Path "$schemas_wildcard" -Force -File)
if ($schemas.Length -eq 0)
{
    Write-Host "Error: no SQL schemas available in `"$schemas_dir`"."
    exit
}

foreach($schema in $schemas)
{
    $out_schema_path = "$schemas_outdir\" + $schema.BaseName + ".c"
    $out_schema = (Test-Path -Path "$out_schema_path" -PathType Leaf)
    if ($out_schema -eq $False)
    {
        Write-Host "File `"$out_schema_path`" not available. Converting SQL schema..."
        $var_name = ($schema.Name).replace(".","_")
        $c_code = "const char *$var_name = `"" + (Get-Content $schema.FullName -Raw).replace("`n","") + "`";"
        Set-Content -Value "$c_code" -Path "$out_schema_path" -Force
    } else {
        Write-Host "File `"$out_schema_path`" already available."
    }
}

# VERSION file path
$version_path = "$dir_prefix\VERSION"

# Get VERSION file contents
$version = (Get-Content "$version_path")

# Perform a regex to get the version number for the URL
$ver_match = ($version -match "^v(?<version>\d+\.\d+)")
if ($ver_match -eq $False)
{
    Write-Host "Error: invalid VERSION file in `"$version_path`"."
    exit
}

# Update variable
$version = $matches['version']

# Additional constants
$resources_url = "https://packages.wazuh.com/deps/$version"
#$external_res = "cJSON","curl","openssl","sqlite","zlib"
$external_res = "cJSON","sqlite"
$external_dir = "$dir_prefix\external"

foreach($resource in $external_res)
{
    $external_url = "$resources_url/$resource.tar.gz"
    $external_tar = "$external_dir\$resource.tar.gz"
    
    # Check if the library has been downloaded already
    $tarball = (Test-Path -Path "$external_tar" -PathType Leaf)
    if ($tarball -eq $False)
    {
        # Download library
        Write-Host "Library `"$resource`" not available."
        downloadFile $external_url "$external_tar"
        Write-Host "Expanding tarball from library `"$resource`"..."
        Extract-CompressedFile "$external_tar" "$external_dir"
    } else {
        Write-Host "Library `"$resource`" already available."
    }
}

# Get pthreads-w32 from SourceForge
$pthreads_zip = "pthreads-w32-2-9-1-release.zip"
$pthreads_url = "https://sourceforge.net/projects/pthreads4w/files/$pthreads_zip/download"
$pthreads_path = "$external_dir\$pthreads_zip"
$pthreads_dst = "$external_dir\pthreads"

createDestDir "$pthreads_dst"

$pthreads = (Test-Path -Path "$pthreads_path" -PathType Leaf)
if ($pthreads -eq $False)
{
    Write-Host "Library `"pthreads`" not available."
    downloadFile $pthreads_url "$pthreads_path"
    Write-Host "Expanding ZIP archive from library `"pthreads`"..."
    Extract-CompressedFile "$pthreads_path" "$pthreads_dst"
} else {
    Write-Host "Library `"pthreads`" already available."
}
