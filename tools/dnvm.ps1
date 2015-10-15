#Requires -Version 2

if (Test-Path env:WEBSITE_SITE_NAME)
{
    # This script is run in Azure Web Sites
    # Disable progress indicator
    $ProgressPreference = "SilentlyContinue"
}

$ScriptPath = $MyInvocation.MyCommand.Definition

$Script:UseWriteHost = $true
function _WriteDebug($msg) {
    if($Script:UseWriteHost) {
        try {
            Write-Debug $msg
        } catch {
            $Script:UseWriteHost = $false
            _WriteDebug $msg
        }
    }
}

function _WriteOut {
    param(
        [Parameter(Mandatory=$false, Position=0, ValueFromPipeline=$true)][string]$msg,
        [Parameter(Mandatory=$false)][ConsoleColor]$ForegroundColor,
        [Parameter(Mandatory=$false)][ConsoleColor]$BackgroundColor,
        [Parameter(Mandatory=$false)][switch]$NoNewLine)

    if($__TestWriteTo) {
        $cur = Get-Variable -Name $__TestWriteTo -ValueOnly -Scope Global -ErrorAction SilentlyContinue
        $val = $cur + "$msg"
        if(!$NoNewLine) {
            $val += [Environment]::NewLine
        }
        Set-Variable -Name $__TestWriteTo -Value $val -Scope Global -Force
        return
    }

    if(!$Script:UseWriteHost) {
        if(!$msg) {
            $msg = ""
        }
        if($NoNewLine) {
            [Console]::Write($msg)
        } else {
            [Console]::WriteLine($msg)
        }
    }
    else {
        try {
            if(!$ForegroundColor) {
                $ForegroundColor = $host.UI.RawUI.ForegroundColor
            }
            if(!$BackgroundColor) {
                $BackgroundColor = $host.UI.RawUI.BackgroundColor
            }

            Write-Host $msg -ForegroundColor:$ForegroundColor -BackgroundColor:$BackgroundColor -NoNewLine:$NoNewLine
        } catch {
            $Script:UseWriteHost = $false
            _WriteOut $msg
        }
    }
}

### Constants
$ProductVersion="1.0.0"
$BuildVersion="beta8-15521"
$Authors="Microsoft Open Technologies, Inc."

# If the Version hasn't been replaced...
# We can't compare directly with the build version token
# because it'll just get replaced here as well :)
if($BuildVersion.StartsWith("{{")) {
    # We're being run from source code rather than the "compiled" artifact
    $BuildVersion = "HEAD"
}
$FullVersion="$ProductVersion-$BuildVersion"

Set-Variable -Option Constant "CommandName" ([IO.Path]::GetFileNameWithoutExtension($ScriptPath))
Set-Variable -Option Constant "CommandFriendlyName" ".NET Version Manager"
Set-Variable -Option Constant "DefaultUserDirectoryName" ".dnx"
Set-Variable -Option Constant "DefaultGlobalDirectoryName" "Microsoft DNX"
Set-Variable -Option Constant "OldUserDirectoryNames" @(".kre", ".k")
Set-Variable -Option Constant "RuntimePackageName" "dnx"
Set-Variable -Option Constant "DefaultFeed" "https://www.nuget.org/api/v2"
Set-Variable -Option Constant "DefaultFeedKey" "DNX_FEED"
Set-Variable -Option Constant "DefaultUnstableFeed" "https://www.myget.org/F/aspnetrelease/api/v2"
Set-Variable -Option Constant "DefaultUnstableFeedKey" "DNX_UNSTABLE_FEED"
Set-Variable -Option Constant "CrossGenCommand" "dnx-crossgen"
Set-Variable -Option Constant "OldCrossGenCommand" "k-crossgen"
Set-Variable -Option Constant "CommandPrefix" "dnvm-"
Set-Variable -Option Constant "DefaultArchitecture" "x86"
Set-Variable -Option Constant "DefaultRuntime" "clr"
Set-Variable -Option Constant "AliasExtension" ".txt"
Set-Variable -Option Constant "DefaultOperatingSystem" "win"

# These are intentionally using "%" syntax. The environment variables are expanded whenever the value is used.
Set-Variable -Option Constant "OldUserHomes" @("%USERPROFILE%\.kre", "%USERPROFILE%\.k")
Set-Variable -Option Constant "DefaultUserHome" "%USERPROFILE%\$DefaultUserDirectoryName"
Set-Variable -Option Constant "HomeEnvVar" "DNX_HOME"

Set-Variable -Option Constant "RuntimeShortFriendlyName" "DNX"

Set-Variable -Option Constant "DNVMUpgradeUrl" "https://raw.githubusercontent.com/aspnet/Home/dev/dnvm.ps1"

Set-Variable -Option Constant "AsciiArt" @"
   ___  _  ___   ____  ___
  / _ \/ |/ / | / /  |/  /
 / // /    /| |/ / /|_/ / 
/____/_/|_/ |___/_/  /_/  
"@

$ExitCodes = @{
    "Success"                   = 0
    "AliasDoesNotExist"         = 1001
    "UnknownCommand"            = 1002
    "InvalidArguments"          = 1003
    "OtherError"                = 1004
    "NoSuchPackage"             = 1005
    "NoRuntimesOnFeed"          = 1006
}

$ColorScheme = $DnvmColors
if(!$ColorScheme) {
    $ColorScheme = @{
        "Banner"=[ConsoleColor]::Cyan
        "RuntimeName"=[ConsoleColor]::Yellow
        "Help_Header"=[ConsoleColor]::Yellow
        "Help_Switch"=[ConsoleColor]::Green
        "Help_Argument"=[ConsoleColor]::Cyan
        "Help_Optional"=[ConsoleColor]::Gray
        "Help_Command"=[ConsoleColor]::DarkYellow
        "Help_Executable"=[ConsoleColor]::DarkYellow
        "Feed_Name"=[ConsoleColor]::Cyan
        "Warning" = [ConsoleColor]::Yellow
        "Error" = [ConsoleColor]::Red
        "ActiveRuntime" = [ConsoleColor]::Cyan
    }
}

Set-Variable -Option Constant "OptionPadding" 20
Set-Variable -Option Constant "CommandPadding" 15

# Test Control Variables
if($__TeeTo) {
    _WriteDebug "Saving output to '$__TeeTo' variable"
    Set-Variable -Name $__TeeTo -Value "" -Scope Global -Force
}

# Commands that have been deprecated but do still work.
$DeprecatedCommands = @("unalias")

# Load Environment variables
$RuntimeHomes = $(if (Test-Path "env:\$HomeEnvVar") {Get-Content "env:\$HomeEnvVar"})
$UserHome = $env:DNX_USER_HOME
$GlobalHome = $env:DNX_GLOBAL_HOME
$ActiveFeed = $(if (Test-Path "env:\$DefaultFeedKey") {Get-Content "env:\$DefaultFeedKey"})
$ActiveUnstableFeed = $(if (Test-Path "env:\$DefaultUnstableFeedKey") {Get-Content "env:\$DefaultUnstableFeedKey"})

# Default Exit Code
$Script:ExitCode = $ExitCodes.Success

############################################################
### Below this point, the terms "DNVM", "DNX", etc.      ###
### should never be used. Instead, use the Constants     ###
### defined above                                        ###
############################################################
# An exception to the above: The commands are defined by functions
# named "dnvm-[command name]" so that extension functions can be added

$StartPath = $env:PATH

if($CmdPathFile) {
    if(Test-Path $CmdPathFile) {
        _WriteDebug "Cleaning old CMD PATH file: $CmdPathFile"
        Remove-Item $CmdPathFile -Force
    }
    _WriteDebug "Using CMD PATH file: $CmdPathFile"
}

# Determine the default installation directory (UserHome)
if(!$UserHome) {
    if ($RuntimeHomes) {
    _WriteDebug "Detecting User Home..."
    $pf = $env:ProgramFiles
    if(Test-Path "env:\ProgramFiles(x86)") {
        $pf32 = Get-Content "env:\ProgramFiles(x86)"
    }

    # Canonicalize so we can do StartsWith tests
    if(!$pf.EndsWith("\")) { $pf += "\" }
    if($pf32 -and !$pf32.EndsWith("\")) { $pf32 += "\" }

      $UserHome = $RuntimeHomes.Split(";") | Where-Object {
        # Take the first path that isn't under program files
        !($_.StartsWith($pf) -or $_.StartsWith($pf32))
    } | Select-Object -First 1

    _WriteDebug "Found: $UserHome"
    }
    
    if(!$UserHome) {
        $UserHome = "$DefaultUserHome"
    }
}
$UserHome = [Environment]::ExpandEnvironmentVariables($UserHome)

# Determine the default global installation directory (GlobalHome)
if(!$GlobalHome) {
    if($env:ProgramData) {
        $GlobalHome = "$env:ProgramData\$DefaultGlobalDirectoryName"
    } else {
        $GlobalHome = "$env:AllUsersProfile\$DefaultGlobalDirectoryName"
    }
}
$GlobalHome = [Environment]::ExpandEnvironmentVariables($GlobalHome)

# Determine where runtimes can exist (RuntimeHomes)
if(!$RuntimeHomes) {
    # Set up a default value for the runtime home
    $UnencodedHomes = "$UserHome;$GlobalHome"
} elseif ($RuntimeHomes.StartsWith(';')) {
    _WriteOut "Ignoring invalid $HomeEnvVar; value was '$RuntimeHomes'" -ForegroundColor $ColorScheme.Warning
    Clean-HomeEnv($true)

    # Use default instead.
    $UnencodedHomes = "$UserHome;$GlobalHome"
} else {
    $UnencodedHomes = $RuntimeHomes
}

$UnencodedHomes = $UnencodedHomes.Split(";")
$RuntimeHomes = $UnencodedHomes | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_) }
$RuntimeDirs = $RuntimeHomes | ForEach-Object { Join-Path $_ "runtimes" }

_WriteDebug ""
_WriteDebug "=== Running $CommandName ==="
_WriteDebug "Runtime Homes: $RuntimeHomes"
_WriteDebug "User Home: $UserHome"
$AliasesDir = Join-Path $UserHome "alias"
$RuntimesDir = Join-Path $UserHome "runtimes"
$GlobalRuntimesDir = Join-Path $GlobalHome "runtimes"
$Aliases = $null

### Helper Functions
# Remove $HomeEnv from process and user environment.
# Called when current value is invalid or after installing files to default location.
function Clean-HomeEnv {
    param([switch]$SkipUserEnvironment)

    if (Test-Path "env:\$HomeEnvVar") {
        _WriteOut "Removing Process $HomeEnvVar"
        Set-Content "env:\$HomeEnvVar" $null
    }

    if (!$SkipUserEnvironment -and [Environment]::GetEnvironmentVariable($HomeEnvVar, "User")) {
        _WriteOut "Removing User $HomeEnvVar"
        [Environment]::SetEnvironmentVariable($HomeEnvVar, $null, "User")
    }
}

# Checks if a specified file exists in the destination folder and if not, copies the file
# to the destination folder. 
function Safe-Filecopy {
    param(
        [Parameter(Mandatory=$true, Position=0)] $Filename, 
        [Parameter(Mandatory=$true, Position=1)] $SourceFolder,
        [Parameter(Mandatory=$true, Position=2)] $DestinationFolder)

    # Make sure the destination folder is created if it doesn't already exist.
    if(!(Test-Path $DestinationFolder)) {
        _WriteOut "Creating destination folder '$DestinationFolder' ... "
        
        New-Item -Type Directory $Destination | Out-Null
    }

    $sourceFilePath = Join-Path $SourceFolder $Filename
    $destFilePath = Join-Path $DestinationFolder $Filename

    if(Test-Path $sourceFilePath) {
        _WriteOut "Installing '$Filename' to '$DestinationFolder' ... "

        if (Test-Path $destFilePath) {
            _WriteOut "  Skipping: file already exists" -ForegroundColor Yellow
        }
        else {
            Copy-Item $sourceFilePath $destFilePath -Force
        }
    }
    else {
        _WriteOut "WARNING: Unable to install: Could not find '$Filename' in '$SourceFolder'. " 
    }
}

$OSRuntimeDefaults = @{
    "win"="clr";
    "linux"="mono";
    "darwin"="mono";
}

$RuntimeBitnessDefaults = @{
    "clr"="x86";
    "coreclr"="x64";
}

function GetRuntimeInfo($Architecture, $Runtime, $OS, $Version) {
    $runtimeInfo = @{
        "Architecture"="$Architecture";
        "Runtime"="$Runtime";
        "OS"="$OS";
        "Version"="$Version";
    }

    if([String]::IsNullOrEmpty($runtimeInfo.OS)) {
        if($runtimeInfo.Runtime -eq "mono"){
            #If OS is empty and you are asking for mono, i.e `dnvm install latest -os mono` then we don't know what OS to pick. It could be Linux or Darwin.
            #we could just arbitrarily pick one but it will probably be wrong as often as not.
            #If Mono can run on Windows then this error doesn't make sense anymore.
            throw "Unable to determine an operating system for a $($runtimeInfo.Runtime) runtime. You must specify which OS to use with the OS parameter."
        }
        $runtimeInfo.OS = $DefaultOperatingSystem
    }

    if($runtimeInfo.OS -eq "osx") {
        $runtimeInfo.OS = "darwin"
    }

    if([String]::IsNullOrEmpty($runtimeInfo.Runtime)) {
        $runtimeInfo.Runtime = $OSRuntimeDefaults.Get_Item($runtimeInfo.OS)
    }

    if([String]::IsNullOrEmpty($runtimeInfo.Architecture)) {
        $runtimeInfo.Architecture = $RuntimeBitnessDefaults.Get_Item($RuntimeInfo.Runtime)
    }
    
    $runtimeObject = New-Object PSObject -Property $runtimeInfo
    
    $runtimeObject | Add-Member -MemberType ScriptProperty -Name RuntimeId -Value {
        if($this.Runtime -eq "mono") {
            "$RuntimePackageName-$($this.Runtime)".ToLowerInvariant()
        } else {
            "$RuntimePackageName-$($this.Runtime)-$($this.OS)-$($this.Architecture)".ToLowerInvariant()
        }
    }

    $runtimeObject | Add-Member -MemberType ScriptProperty -Name RuntimeName -Value {
        "$($this.RuntimeId).$($this.Version)"
    }

    $runtimeObject
}

function Write-Usage {
    _WriteOut -ForegroundColor $ColorScheme.Banner $AsciiArt
    _WriteOut "$CommandFriendlyName v$FullVersion"
    if(!$Authors.StartsWith("{{")) {
        _WriteOut "By $Authors"
    }
    _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Header "usage:"
    _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Executable " $CommandName"
    _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Command " <command>"
    _WriteOut -ForegroundColor $ColorScheme.Help_Argument " [<arguments...>]"
}

function Write-Feeds {
    _WriteOut
    _WriteOut -ForegroundColor $ColorScheme.Help_Header "Current feed settings:"
    _WriteOut -NoNewline -ForegroundColor $ColorScheme.Feed_Name "Default Stable: "
    _WriteOut "$DefaultFeed"
    _WriteOut -NoNewline -ForegroundColor $ColorScheme.Feed_Name "Default Unstable: "
    _WriteOut "$DefaultUnstableFeed"
    _WriteOut -NoNewline -ForegroundColor $ColorScheme.Feed_Name "Current Stable Override: "
    if($ActiveFeed) {
        _WriteOut "$ActiveFeed"
    } else {
        _WriteOut "<none>"
    }
    _WriteOut -NoNewline -ForegroundColor $ColorScheme.Feed_Name "Current Unstable Override: "
    if($ActiveUnstableFeed) {
        _WriteOut "$ActiveUnstableFeed"
    } else {
        _WriteOut "<none>"
    }
    _WriteOut
    _WriteOut -NoNewline "    To use override feeds, set "
    _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Executable "$DefaultFeedKey"
    _WriteOut -NoNewline " and "
    _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Executable "$DefaultUnstableFeedKey"
    _WriteOut -NoNewline " environment keys respectively"
    _WriteOut
}

function Get-RuntimeAlias {
    if($Aliases -eq $null) {
        _WriteDebug "Scanning for aliases in $AliasesDir"
        if(Test-Path $AliasesDir) {
            $Aliases = @(Get-ChildItem ($UserHome + "\alias\") | Select-Object @{label='Alias';expression={$_.BaseName}}, @{label='Name';expression={Get-Content $_.FullName }}, @{label='Orphan';expression={-Not (Test-Path ($RuntimesDir + "\" + (Get-Content $_.FullName)))}})
        } else {
            $Aliases = @()
        }
    }
    $Aliases
}

function IsOnPath {
    param($dir)

    $env:Path.Split(';') -icontains $dir
}

function Get-RuntimeAliasOrRuntimeInfo(
    [Parameter(Mandatory=$true)][string]$Version,
    [Parameter()][string]$Architecture,
    [Parameter()][string]$Runtime,
    [Parameter()][string]$OS) {

    $aliasPath = Join-Path $AliasesDir "$Version$AliasExtension"

    if(Test-Path $aliasPath) {
        $BaseName = Get-Content $aliasPath

        if(!$Architecture) {
        $Architecture = Get-PackageArch $BaseName
        }
        if(!$Runtime) {
        $Runtime = Get-PackageRuntime $BaseName
        }
        $Version = Get-PackageVersion $BaseName
        $OS = Get-PackageOS $BaseName
    }
    
    GetRuntimeInfo $Architecture $Runtime $OS $Version 
}

filter List-Parts {
    param($aliases, $items)

	$location = ""

	$binDir = Join-Path $_.FullName "bin"
	if ((Test-Path $binDir)) {
        $location = $_.Parent.FullName
    }
	$active = IsOnPath $binDir

    $fullAlias=""
    $delim=""

    foreach($alias in $aliases) {
        if($_.Name.Split('\', 2) -contains $alias.Name) {
            $fullAlias += $delim + $alias.Alias + (&{if($alias.Orphan){" (missing)"}})
            $delim = ", "
        }
    }

    $parts1 = $_.Name.Split('.', 2)
    $parts2 = $parts1[0].Split('-', 4)

    if($parts1[0] -eq "$RuntimePackageName-mono") {
        $parts2 += "linux/osx"
        $parts2 += "x86/x64"
    }

    $aliasUsed = ""
    if($items) {
    $aliasUsed = $items | ForEach-Object {
        if($_.Architecture -eq $parts2[3] -and $_.Runtime -eq $parts2[1] -and $_.OperatingSystem -eq $parts2[2] -and $_.Version -eq $parts1[1]) {
            return $true;
        }
        return $false;
    }
    }

    if($aliasUsed -eq $true) {
        $fullAlias = ""
    }

    return New-Object PSObject -Property @{
        Active = $active
        Version = $parts1[1]
        Runtime = $parts2[1]
        OperatingSystem = $parts2[2]
        Architecture = $parts2[3]
        Location = $location
        Alias = $fullAlias
    }
}

function Read-Alias($Name) {
    _WriteDebug "Listing aliases matching '$Name'"

    $aliases = Get-RuntimeAlias

    $result = @($aliases | Where-Object { !$Name -or ($_.Alias.Contains($Name)) })
    if($Name -and ($result.Length -eq 1)) {
        _WriteOut "Alias '$Name' is set to '$($result[0].Name)'"
    } elseif($Name -and ($result.Length -eq 0)) {
        _WriteOut "Alias does not exist: '$Name'"
        $Script:ExitCode = $ExitCodes.AliasDoesNotExist
    } else {
        $result
    }
}

function Write-Alias {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Version,
        [Parameter(Mandatory=$false)][string]$Architecture,
        [Parameter(Mandatory=$false)][string]$Runtime,
        [Parameter(Mandatory=$false)][string]$OS)

    # If the first character is non-numeric, it's a full runtime name
    if(![Char]::IsDigit($Version[0])) {
        $runtimeInfo = GetRuntimeInfo $(Get-PackageArch $Version) $(Get-PackageRuntime $Version) $(Get-PackageOS $Version) $(Get-PackageVersion $Version)
    } else {
        $runtimeInfo = GetRuntimeInfo $Architecture $Runtime $OS $Version
    }

    $aliasFilePath = Join-Path $AliasesDir "$Name.txt"
    $action = if (Test-Path $aliasFilePath) { "Updating" } else { "Setting" }
    
    if(!(Test-Path $AliasesDir)) {
        _WriteDebug "Creating alias directory: $AliasesDir"
        New-Item -Type Directory $AliasesDir | Out-Null
    }
    _WriteOut "$action alias '$Name' to '$($runtimeInfo.RuntimeName)'"
    $runtimeInfo.RuntimeName | Out-File $aliasFilePath ascii
}

function Delete-Alias {
    param(
        [Parameter(Mandatory=$true)][string]$Name)

    $aliasPath = Join-Path $AliasesDir "$Name.txt"
    if (Test-Path -literalPath "$aliasPath") {
        _WriteOut "Removing alias $Name"

        # Delete with "-Force" because we already confirmed above
        Remove-Item -literalPath $aliasPath -Force
    } else {
        _WriteOut "Cannot remove alias '$Name'. It does not exist."
        $Script:ExitCode = $ExitCodes.AliasDoesNotExist # Return non-zero exit code for scripting
    }
}

function Apply-Proxy {
param(
  [System.Net.WebClient] $wc,
  [string]$Proxy
)
  if (!$Proxy) {
    $Proxy = $env:http_proxy
  }
  if ($Proxy) {
    $wp = New-Object System.Net.WebProxy($Proxy)
    $pb = New-Object UriBuilder($Proxy)
    if (!$pb.UserName) {
        $wp.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    } else {
        $wp.Credentials = New-Object System.Net.NetworkCredential($pb.UserName, $pb.Password)
    }
    $wc.Proxy = $wp
  }
}

function Find-Package {
    param(
        $runtimeInfo,
        [string]$Feed,
        [string]$Proxy
    )
    $url = "$Feed/Packages()?`$filter=Id eq '$($runtimeInfo.RuntimeId)' and Version eq '$($runtimeInfo.Version)'"
    Invoke-NuGetWebRequest $runtimeInfo.RuntimeId $url $Proxy
}

function Find-Latest {
    param(
        $runtimeInfo,
        [Parameter(Mandatory=$true)]
        [string]$Feed,
        [string]$Proxy
    )

    _WriteOut "Determining latest version"
    $RuntimeId = $runtimeInfo.RuntimeId
    _WriteDebug "Latest RuntimeId: $RuntimeId"
    $url = "$Feed/GetUpdates()?packageIds=%27$RuntimeId%27&versions=%270.0%27&includePrerelease=true&includeAllVersions=false"
    Invoke-NuGetWebRequest $RuntimeId $url $Proxy
}

function Invoke-NuGetWebRequest {
    param (
        [string]$RuntimeId,
        [string]$Url,
        [string]$Proxy
    )
    # NOTE: DO NOT use Invoke-WebRequest. It requires PowerShell 4.0!

    $wc = New-Object System.Net.WebClient
    Apply-Proxy $wc -Proxy:$Proxy
    _WriteDebug "Downloading $Url ..."
    try {
        [xml]$xml = $wc.DownloadString($Url)
    } catch {
        $Script:ExitCode = $ExitCodes.NoRuntimesOnFeed
        throw "Unable to find any runtime packages on the feed!"
    }

    $version = Select-Xml "//d:Version" -Namespace @{d='http://schemas.microsoft.com/ado/2007/08/dataservices'} $xml
    if($version) {
        $downloadUrl = (Select-Xml "//d:content/@src" -Namespace @{d='http://www.w3.org/2005/Atom'} $xml).Node.value
        _WriteDebug "Found $version at $downloadUrl"
        @{ Version = $version; DownloadUrl = $downloadUrl }
    } else {
        throw "There are no runtimes matching the name $RuntimeId on feed $feed."
    }
}

function Get-PackageVersion() {
    param(
        [string] $runtimeFullName
    )
    return $runtimeFullName -replace '[^.]*.(.*)', '$1'
}

function Get-PackageRuntime() {
    param(
        [string] $runtimeFullName
    )
    return $runtimeFullName -replace "$RuntimePackageName-([^-]*).*", '$1'
}

function Get-PackageArch() {
    param(
        [string] $runtimeFullName
    )
    return $runtimeFullName -replace "$RuntimePackageName-[^-]*-[^-]*-([^.]*).*", '$1'
}

function Get-PackageOS() {
    param(
        [string] $runtimeFullName
    )
    $runtimeFullName -replace "$RuntimePackageName-[^-]*-([^-]*)-[^.]*.*", '$1'
}

function Download-Package() {
    param(
        $runtimeInfo,
        [Parameter(Mandatory=$true)]
        [string]$DownloadUrl,
        [string]$DestinationFile,
        [Parameter(Mandatory=$true)]
        [string]$Feed,
        [string]$Proxy
    )
    
    _WriteOut "Downloading $($runtimeInfo.RuntimeName) from $feed"
    $wc = New-Object System.Net.WebClient
    try {
      Apply-Proxy $wc -Proxy:$Proxy     
      _WriteDebug "Downloading $DownloadUrl ..."

      Register-ObjectEvent $wc DownloadProgressChanged -SourceIdentifier WebClient.ProgressChanged -action {
        $Global:downloadData = $eventArgs
      } | Out-Null

      Register-ObjectEvent $wc DownloadFileCompleted -SourceIdentifier WebClient.ProgressComplete -action {
        $Global:downloadData = $eventArgs
        $Global:downloadCompleted = $true
      } | Out-Null

      $wc.DownloadFileAsync($DownloadUrl, $DestinationFile)

      while(-not $Global:downloadCompleted){
        $percent = $Global:downloadData.ProgressPercentage
        $totalBytes = $Global:downloadData.TotalBytesToReceive
        $receivedBytes = $Global:downloadData.BytesReceived
        If ($percent -ne $null) {
            Write-Progress -Activity ("Downloading $RuntimeShortFriendlyName from $DownloadUrl") `
                -Status ("Downloaded $($Global:downloadData.BytesReceived) of $($Global:downloadData.TotalBytesToReceive) bytes") `
                -PercentComplete $percent -Id 2 -ParentId 1
        }
      }

      if($Global:downloadData.Error) {
        if($Global:downloadData.Error.Response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound){
            throw "The server returned a 404 (NotFound). This is most likely caused by the feed not having the version that you typed. Check that you typed the right version and try again. Other possible causes are the feed doesn't have a $RuntimeShortFriendlyName of the right name format or some other error caused a 404 on the server."
        } else {
            throw "Unable to download package: {0}" -f $Global:downloadData.Error.Message
        }
      }

      Write-Progress -Status "Done" -Activity ("Downloading $RuntimeShortFriendlyName from $DownloadUrl") -Id 2 -ParentId 1 -Completed
    }
    finally {
        Remove-Variable downloadData -Scope "Global"
        Remove-Variable downloadCompleted -Scope "Global"
        Unregister-Event -SourceIdentifier WebClient.ProgressChanged
        Unregister-Event -SourceIdentifier WebClient.ProgressComplete
        $wc.Dispose()
    }
}

function Unpack-Package([string]$DownloadFile, [string]$UnpackFolder) {
    _WriteDebug "Unpacking $DownloadFile to $UnpackFolder"

    $compressionLib = [System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem')

    if($compressionLib -eq $null) {
      try {
          # Shell will not recognize nupkg as a zip and throw, so rename it to zip
          $runtimeZip = [System.IO.Path]::ChangeExtension($DownloadFile, "zip")
          Rename-Item $DownloadFile $runtimeZip
          # Use the shell to uncompress the nupkg
          $shell_app=new-object -com shell.application
          $zip_file = $shell_app.namespace($runtimeZip)
          $destination = $shell_app.namespace($UnpackFolder)
          $destination.Copyhere($zip_file.items(), 0x14) #0x4 = don't show UI, 0x10 = overwrite files
      }
      finally {
        # Clean up the package file itself.
        Remove-Item $runtimeZip -Force
      }
    } else {
        [System.IO.Compression.ZipFile]::ExtractToDirectory($DownloadFile, $UnpackFolder)
        
        # Clean up the package file itself.
        Remove-Item $DownloadFile -Force
    }

    If (Test-Path -LiteralPath ($UnpackFolder + "\[Content_Types].xml")) {
        Remove-Item -LiteralPath ($UnpackFolder + "\[Content_Types].xml")
    }
    If (Test-Path ($UnpackFolder + "\_rels\")) {
        Remove-Item -LiteralPath ($UnpackFolder + "\_rels\") -Force -Recurse
    }
    If (Test-Path ($UnpackFolder + "\package\")) {
        Remove-Item -LiteralPath ($UnpackFolder + "\package\") -Force -Recurse
    }
}

function Get-RuntimePath($runtimeFullName) {
    _WriteDebug "Resolving $runtimeFullName"
    foreach($RuntimeHome in $RuntimeHomes) {
        $runtimeBin = "$RuntimeHome\runtimes\$runtimeFullName\bin"
        _WriteDebug " Candidate $runtimeBin"
        if (Test-Path $runtimeBin) {
            _WriteDebug " Found in $runtimeBin"
            return $runtimeBin
        }
    }
    return $null
}

function Change-Path() {
    param(
        [string] $existingPaths,
        [string] $prependPath,
        [string[]] $removePaths
    )
    _WriteDebug "Updating value to prepend '$prependPath' and remove '$removePaths'"
    
    $newPath = $prependPath
    foreach($portion in $existingPaths.Split(';')) {
        if(![string]::IsNullOrEmpty($portion)) {
            $skip = $portion -eq ""
            foreach($removePath in $removePaths) {
                if(![string]::IsNullOrEmpty($removePath)) {
                    $removePrefix = if($removePath.EndsWith("\")) { $removePath } else { "$removePath\" }

                    if ($removePath -and (($portion -eq $removePath) -or ($portion.StartsWith($removePrefix)))) {
                        _WriteDebug " Removing '$portion' because it matches '$removePath'"
                        $skip = $true
                    }
                }
            }
            if (!$skip) {
                if(![String]::IsNullOrEmpty($newPath)) {
                    $newPath += ";"
                }
                $newPath += $portion
            }
        }
    }
    return $newPath
}

function Set-Path() {
    param(
        [string] $newPath
    )

    $env:PATH = $newPath

    if($CmdPathFile) {
        $Parent = Split-Path -Parent $CmdPathFile
        if(!(Test-Path $Parent)) {
            New-Item -Type Directory $Parent -Force | Out-Null
        }
        _WriteDebug " Writing PATH file for CMD script"
        @"
SET "PATH=$newPath"
"@ | Out-File $CmdPathFile ascii
    }
}

function Ngen-Library(
    [Parameter(Mandatory=$true)]
    [string]$runtimeBin,

    [ValidateSet("x86", "x64")]
    [Parameter(Mandatory=$true)]
    [string]$architecture) {

    if ($architecture -eq 'x64') {
        $regView = [Microsoft.Win32.RegistryView]::Registry64
    }
    elseif ($architecture -eq 'x86') {
        $regView = [Microsoft.Win32.RegistryView]::Registry32
    }
    else {
        _WriteOut "Installation does not understand architecture $architecture, skipping ngen..."
        return
    }

    $regHive = [Microsoft.Win32.RegistryHive]::LocalMachine
    $regKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($regHive, $regView)
    $frameworkPath = $regKey.OpenSubKey("SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").GetValue("InstallPath")
    $ngenExe = Join-Path $frameworkPath 'ngen.exe'

    $ngenCmds = ""
    foreach ($bin in Get-ChildItem $runtimeBin -Filter "Microsoft.CodeAnalysis.CSharp.dll") {
        $ngenCmds += "$ngenExe install $($bin.FullName);"
    }

    $ngenProc = Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList "-ExecutionPolicy unrestricted & $ngenCmds" -Wait -PassThru -WindowStyle Hidden
}

function Is-Elevated() {
    $user = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    return $user.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

### Commands

<#
.SYNOPSIS
    Updates DNVM to the latest version.
.PARAMETER Proxy
    Use the given address as a proxy when accessing remote server
#>
function dnvm-update-self {
    param(
        [Parameter(Mandatory=$false)] 
        [string]$Proxy)

    _WriteOut "Updating $CommandName from $DNVMUpgradeUrl"
    $wc = New-Object System.Net.WebClient
    Apply-Proxy $wc -Proxy:$Proxy
    
    $dnvmFile = Join-Path $PSScriptRoot "dnvm.ps1"
    $tempDnvmFile = Join-Path $PSScriptRoot "temp"
    $backupFilePath = Join-Path $PSSCriptRoot "dnvm.ps1.bak"

    $wc.DownloadFile($DNVMUpgradeUrl, $tempDnvmFile)

    if(Test-Path $backupFilePath) {
        Remove-Item $backupFilePath -Force
    }

    Rename-Item $dnvmFile $backupFilePath
    Rename-Item $tempDnvmFile $dnvmFile
}

<#
.SYNOPSIS
    Displays a list of commands, and help for specific commands
.PARAMETER Command
    A specific command to get help for
#>
function dnvm-help {
    [CmdletBinding(DefaultParameterSetName="GeneralHelp")]
    param(
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="SpecificCommand")][string]$Command,
        [switch]$PassThru)

    if($Command) {
        $cmd = Get-Command "dnvm-$Command" -ErrorAction SilentlyContinue
        if(!$cmd) {
            _WriteOut "No such command: $Command"
            dnvm-help
            $Script:ExitCodes = $ExitCodes.UnknownCommand
            return
        }
        if($Host.Version.Major -lt 3) {
            $help = Get-Help "dnvm-$Command"
        } else {
            $help = Get-Help "dnvm-$Command" -ShowWindow:$false
        }
        if($PassThru -Or $Host.Version.Major -lt 3) {
            $help
        } else {
            _WriteOut -ForegroundColor $ColorScheme.Help_Header "$CommandName $Command"
            _WriteOut "  $($help.Synopsis.Trim())"
            _WriteOut
            _WriteOut -ForegroundColor $ColorScheme.Help_Header "usage:"
            $help.Syntax.syntaxItem | ForEach-Object {
                _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Executable "  $CommandName "
                _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Command "$Command"
                if($_.parameter) {
                    $_.parameter | ForEach-Object {
                        $cmdParam = $cmd.Parameters[$_.name]
                        $name = $_.name
                        if($cmdParam.Aliases.Length -gt 0) {
                            $name = $cmdParam.Aliases | Sort-Object | Select-Object -First 1
                        }

                        _WriteOut -NoNewLine " "
                        
                        if($_.required -ne "true") {
                            _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Optional "["
                        }

                        if($_.position -eq "Named") {
                            _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Switch "-$name"
                        }
                        if($_.parameterValue) {
                            if($_.position -eq "Named") {
                                _WriteOut -NoNewLine " "       
                            }
                            _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Argument "<$($_.name)>"
                        }

                        if($_.required -ne "true") {
                            _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Optional "]"
                        }
                    }
                }
                _WriteOut
            }

            if($help.parameters -and $help.parameters.parameter) {
                _WriteOut
                _WriteOut -ForegroundColor $ColorScheme.Help_Header "options:"
                $help.parameters.parameter | ForEach-Object {
                    $cmdParam = $cmd.Parameters[$_.name]
                    $name = $_.name
                    if($cmdParam.Aliases.Length -gt 0) {
                        $name = $cmdParam.Aliases | Sort-Object | Select-Object -First 1
                    }
                    
                    _WriteOut -NoNewLine "  "
                    
                    if($_.position -eq "Named") {
                        _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Switch "-$name".PadRight($OptionPadding)
                    } else {
                        _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Argument "<$($_.name)>".PadRight($OptionPadding)
                    }
                    _WriteOut " $($_.description.Text)"
                }
            }

            if($help.description) {
                _WriteOut
                _WriteOut -ForegroundColor $ColorScheme.Help_Header "remarks:"
                $help.description.Text.Split(@("`r", "`n"), "RemoveEmptyEntries") | 
                    ForEach-Object { _WriteOut "  $_" }
            }

            if($DeprecatedCommands -contains $Command) {
                _WriteOut "This command has been deprecated and should not longer be used"
            }
        }
    } else {
        Write-Usage
        Write-Feeds
        _WriteOut
        _WriteOut -ForegroundColor $ColorScheme.Help_Header "commands: "
        Get-Command "$CommandPrefix*" | 
            ForEach-Object {
                if($Host.Version.Major -lt 3) {
                    $h = Get-Help $_.Name
                } else {
                    $h = Get-Help $_.Name -ShowWindow:$false
                }
                $name = $_.Name.Substring($CommandPrefix.Length)
                if($DeprecatedCommands -notcontains $name) {
                    _WriteOut -NoNewLine "    "
                    _WriteOut -NoNewLine -ForegroundColor $ColorScheme.Help_Command $name.PadRight($CommandPadding)
                    _WriteOut " $($h.Synopsis.Trim())"
                }
            }
    }
}

filter ColorActive {
    param([string] $color)
    $lines = $_.Split("`n")
    foreach($line in $lines) {
        if($line.Contains("*")){
            _WriteOut -ForegroundColor $ColorScheme.ActiveRuntime $line 
        } else {
            _WriteOut $line
        }
    }
}

<#
.SYNOPSIS
    Displays the DNVM version.
#>
function dnvm-version {
    _WriteOut "$FullVersion"
}

<#
.SYNOPSIS
    Lists available runtimes
.PARAMETER Detailed
    Display more detailed information on each runtime
.PARAMETER PassThru
    Set this switch to return unformatted powershell objects for use in scripting
#>
function dnvm-list {
    param(
        [Parameter(Mandatory=$false)][switch]$PassThru,
        [Parameter(Mandatory=$false)][switch]$Detailed)
    $aliases = Get-RuntimeAlias

    if(-not $PassThru) {
        Check-Runtimes
    }

    $items = @()
    $RuntimeHomes | ForEach-Object {
        _WriteDebug "Scanning $_ for runtimes..."
        if (Test-Path "$_\runtimes") {
            $items += Get-ChildItem "$_\runtimes\$RuntimePackageName-*" | List-Parts $aliases $items
        }
    }

	$aliases | Where-Object {$_.Orphan} | ForEach-Object {
		$items += $_ | Select-Object @{label='Name';expression={$_.Name}}, @{label='FullName';expression={Join-Path $RuntimesDir $_.Name}} | List-Parts $aliases
	}

    if($PassThru) {
        $items
    } else {
        if($items) {
            #TODO: Probably a better way to do this.
            if($Detailed) {
                $items | 
                    Sort-Object Version, Runtime, Architecture, OperatingSystem, Alias | 
                    Format-Table -AutoSize -Property @{name="Active";expression={if($_.Active) { "*" } else { "" }};alignment="center"}, "Version", "Runtime", "Architecture", "OperatingSystem", "Alias", "Location" | Out-String| ColorActive
            } else {
                $items | 
                    Sort-Object Version, Runtime, Architecture, OperatingSystem, Alias | 
                    Format-Table -AutoSize -Property @{name="Active";expression={if($_.Active) { "*" } else { "" }};alignment="center"}, "Version", "Runtime", "Architecture", "OperatingSystem", "Alias" | Out-String | ColorActive
            }
        } else {
            _WriteOut "No runtimes installed. You can run `dnvm install latest` or `dnvm upgrade` to install a runtime."
        }
    }
}

<#
.SYNOPSIS
    Lists and manages aliases
.PARAMETER Name
    The name of the alias to read/create/delete
.PARAMETER Version
    The version to assign to the new alias
.PARAMETER Architecture
    The architecture of the runtime to assign to this alias
.PARAMETER Runtime
    The flavor of the runtime to assign to this alias
.PARAMETER OS
    The operating system that the runtime targets
.PARAMETER Delete
    Set this switch to delete the alias with the specified name
.DESCRIPTION
    If no arguments are provided, this command lists all aliases. If <Name> is provided,
    the value of that alias, if present, is displayed. If <Name> and <Version> are
    provided, the alias <Name> is set to the runtime defined by <Version>, <Architecture>
    (defaults to 'x86') and <Runtime> (defaults to 'clr').

    Finally, if the '-d' switch is provided, the alias <Name> is deleted, if it exists.
    
    NOTE: You cannot create an alias for a non-windows runtime. The intended use case for
    an alias to help make it easier to switch the runtime, and you cannot use a non-windows
    runtime on a windows machine.
#>
function dnvm-alias {
    param(
        [Alias("d")]
        [switch]$Delete,

        [Parameter(Position=0)]
        [string]$Name,

        [Parameter(Position=1)]
        [string]$Version,

        [Alias("arch", "a")]
        [ValidateSet("", "x86", "x64", "arm")]
        [string]$Architecture = "",

        [Alias("r")]
        [ValidateSet("", "clr","coreclr", "mono")]
        [Parameter(ParameterSetName="Write")]
        [string]$Runtime = "",
            
        [ValidateSet("win", "osx", "darwin", "linux")]
        [Parameter(Mandatory=$false,ParameterSetName="Write")]
        [string]$OS = "")

    if($Name -like "help" -or $Name -like "/?") {
        #It is unlikely that the user is trying to read an alias called help, so lets just help them out by displaying help text.
        #If people need an alias called help or one that contains a `?` then we can change this to a prompt.
        dnvm help alias
        return
    }

    if($Version) {
        Write-Alias $Name $Version -Architecture $Architecture -Runtime $Runtime -OS:$OS
    } elseif ($Delete) {
        Delete-Alias $Name
    } else {
        Read-Alias $Name
    }
}

<#
.SYNOPSIS
    [DEPRECATED] Removes an alias
.PARAMETER Name
    The name of the alias to remove
#>
function dnvm-unalias {
    param(
        [Parameter(Mandatory=$true,Position=0)][string]$Name)
    _WriteOut "This command has been deprecated. Use '$CommandName alias -d' instead"
    dnvm-alias -Delete -Name $Name
}

<#
.SYNOPSIS
    Installs the latest version of the runtime and reassigns the specified alias to point at it
.PARAMETER Alias
    The alias to upgrade (default: 'default')
.PARAMETER Architecture
    The processor architecture of the runtime to install (default: x86)
.PARAMETER Runtime
    The runtime flavor to install (default: clr)
.PARAMETER OS
    The operating system that the runtime targets (default: win)
.PARAMETER Force
    Overwrite an existing runtime if it already exists
.PARAMETER Proxy
    Use the given address as a proxy when accessing remote server
.PARAMETER NoNative
    Skip generation of native images
.PARAMETER Ngen
    For CLR flavor only. Generate native images for runtime libraries on Desktop CLR to improve startup time. This option requires elevated privilege and will be automatically turned on if the script is running in administrative mode. To opt-out in administrative mode, use -NoNative switch.
.PARAMETER Unstable
    Upgrade from the unstable dev feed. This will give you the latest development version of the runtime. 
.PARAMETER Global
    Installs to configured global dnx file location (default: C:\ProgramData)
#>
function dnvm-upgrade {
    param(
        [Parameter(Mandatory=$false, Position=0)]
        [string]$Alias = "default",

        [Alias("arch", "a")]
        [ValidateSet("", "x86", "x64", "arm")]
        [Parameter(Mandatory=$false)]
        [string]$Architecture = "",

        [Alias("r")]
        [ValidateSet("", "clr", "coreclr", "mono")]
        [Parameter(Mandatory=$false)]
        [string]$Runtime = "",
        
        [ValidateSet("", "win", "osx", "darwin", "linux")]
        [Parameter(Mandatory=$false)]
        [string]$OS = "",

        [Alias("f")]
        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,

        [Parameter(Mandatory=$false)]
        [switch]$NoNative,

        [Parameter(Mandatory=$false)]
        [switch]$Ngen,

        [Alias("u")]
        [Parameter(Mandatory=$false)]
        [switch]$Unstable,
        
        [Alias("g")]
        [Parameter(Mandatory=$false)]
        [switch]$Global)

    if($OS -ne "win" -and ![String]::IsNullOrEmpty($OS)) {
        #We could remove OS as an option from upgrade, but I want to take this opporunty to educate users about the difference between install and upgrade
        #It's possible we should just do install here instead.
         _WriteOut -ForegroundColor $ColorScheme.Error "You cannot upgrade to a non-windows runtime. Upgrade will download the latest version of the $RuntimeShortFriendlyName and also set it as your machines default. You cannot set the default $RuntimeShortFriendlyName to a non-windows version because you cannot use it to run an application. If you want to install a non-windows $RuntimeShortFriendlyName to package with your application then use 'dnvm install latest -OS:$OS' instead. Install will download the package but not set it as your default."
        $Script:ExitCode = $ExitCodes.OtherError
        return
    }

    dnvm-install "latest" -Alias:$Alias -Architecture:$Architecture -Runtime:$Runtime -OS:$OS -Force:$Force -Proxy:$Proxy -NoNative:$NoNative -Ngen:$Ngen -Unstable:$Unstable -Persistent:$true -Global:$Global
}

<#
.SYNOPSIS
    Installs a version of the runtime
.PARAMETER VersionNuPkgOrAlias
    The version to install from the current channel, the path to a '.nupkg' file to install, 'latest' to
    install the latest available version from the current channel, or an alias value to install an alternate
    runtime or architecture flavor of the specified alias.
.PARAMETER Architecture
    The processor architecture of the runtime to install (default: x86)
.PARAMETER Runtime
    The runtime flavor to install (default: clr)
.PARAMETER OS
    The operating system that the runtime targets (default: win)
.PARAMETER Alias
    Set alias <Alias> to the installed runtime
.PARAMETER Force
    Overwrite an existing runtime if it already exists
.PARAMETER Proxy
    Use the given address as a proxy when accessing remote server
.PARAMETER NoNative
    Skip generation of native images
.PARAMETER Ngen
    For CLR flavor only. Generate native images for runtime libraries on Desktop CLR to improve startup time. This option requires elevated privilege and will be automatically turned on if the script is running in administrative mode. To opt-out in administrative mode, use -NoNative switch.
.PARAMETER Persistent
    Make the installed runtime useable across all processes run by the current user
.PARAMETER Unstable
    Upgrade from the unstable dev feed. This will give you the latest development version of the runtime.
.PARAMETER Global
    Installs to configured global dnx file location (default: C:\ProgramData)
.DESCRIPTION
    A proxy can also be specified by using the 'http_proxy' environment variable
#>
function dnvm-install {
    param(
        [Parameter(Mandatory=$false, Position=0)]
        [string]$VersionNuPkgOrAlias,

        [Alias("arch", "a")]
        [ValidateSet("", "x86", "x64", "arm")]
        [Parameter(Mandatory=$false)]
        [string]$Architecture = "",

        [Alias("r")]
        [ValidateSet("", "clr","coreclr","mono")]
        [Parameter(Mandatory=$false)]
        [string]$Runtime = "",

        [ValidateSet("", "win", "osx", "darwin", "linux")]
        [Parameter(Mandatory=$false)]
        [string]$OS = "",

        [Parameter(Mandatory=$false)]
        [string]$Alias,

        [Alias("f")]
        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [string]$Proxy,

        [Parameter(Mandatory=$false)]
        [switch]$NoNative,

        [Parameter(Mandatory=$false)]
        [switch]$Ngen,

        [Alias("p")]
        [Parameter(Mandatory=$false)]
        [switch]$Persistent,

        [Alias("u")]
        [Parameter(Mandatory=$false)]
        [switch]$Unstable,

        [Alias("g")]
        [Parameter(Mandatory=$false)]
        [switch]$Global)

    $selectedFeed = ""

    if($Unstable) {
        $selectedFeed = $ActiveUnstableFeed
        if(!$selectedFeed) {
            $selectedFeed = $DefaultUnstableFeed
        } else {
            _WriteOut -ForegroundColor $ColorScheme.Warning "Default unstable feed ($DefaultUnstableFeed) is being overridden by the value of the $DefaultUnstableFeedKey environment variable ($ActiveUnstableFeed)"
        }
    } else {
        $selectedFeed = $ActiveFeed
        if(!$selectedFeed) {
            $selectedFeed = $DefaultFeed
        } else {
            _WriteOut -ForegroundColor $ColorScheme.Warning "Default stable feed ($DefaultFeed) is being overridden by the value of the $DefaultFeedKey environment variable ($ActiveFeed)"
        }
    }

    if(!$VersionNuPkgOrAlias) {
        _WriteOut "A version, nupkg path, or the string 'latest' must be provided."
        dnvm-help install
        $Script:ExitCode = $ExitCodes.InvalidArguments
        return
    }

    $IsNuPkg = $VersionNuPkgOrAlias.EndsWith(".nupkg")

    if ($IsNuPkg) {
        if(!(Test-Path $VersionNuPkgOrAlias)) {
            throw "Unable to locate package file: '$VersionNuPkgOrAlias'"
        }
        Write-Progress -Activity "Installing runtime" -Status "Parsing package file name" -Id 1
        $runtimeFullName = [System.IO.Path]::GetFileNameWithoutExtension($VersionNuPkgOrAlias)
        $Architecture = Get-PackageArch $runtimeFullName
        $Runtime = Get-PackageRuntime $runtimeFullName
        $OS = Get-PackageOS $runtimeFullName
        $Version = Get-PackageVersion $runtimeFullName
    } else {
        $aliasPath = Join-Path $AliasesDir "$VersionNuPkgOrAlias$AliasExtension"
        if(Test-Path $aliasPath) {
            $BaseName = Get-Content $aliasPath
            #Check empty checks let us override a given alias property when installing the same again. e.g. `dnvm install default -x64`
            if([String]::IsNullOrEmpty($Architecture)) {
                $Architecture = Get-PackageArch $BaseName
            }
            
            if([String]::IsNullOrEmpty($Runtime)) {
                $Runtime = Get-PackageRuntime $BaseName
            }

            if([String]::IsNullOrEmpty($Version)) {
                $Version = Get-PackageVersion $BaseName
            }
            
            if([String]::IsNullOrEmpty($OS)) {
                $OS = Get-PackageOS $BaseName
            }
        } else {
            $Version = $VersionNuPkgOrAlias
        }
    }

    $runtimeInfo = GetRuntimeInfo $Architecture $Runtime $OS $Version

    if (!$IsNuPkg) {
        if ($VersionNuPkgOrAlias -eq "latest") {
            Write-Progress -Activity "Installing runtime" -Status "Determining latest runtime" -Id 1
            $findPackageResult = Find-Latest -runtimeInfo:$runtimeInfo -Feed:$selectedFeed
        }
        else {
            $findPackageResult = Find-Package -runtimeInfo:$runtimeInfo -Feed:$selectedFeed
        }
        $Version = $findPackageResult.Version
    }

    #If the version is still empty at this point then VersionOrNupkgOrAlias is an actual version.
    if([String]::IsNullOrEmpty($Version)) {
        $Version = $VersionNuPkgOrAlias
    }

    $runtimeInfo.Version = $Version

    _WriteDebug "Preparing to install runtime '$($runtimeInfo.RuntimeName)'"
    _WriteDebug "Architecture: $($runtimeInfo.Architecture)"
    _WriteDebug "Runtime: $($runtimeInfo.Runtime)"
    _WriteDebug "Version: $($runtimeInfo.Version)"
    _WriteDebug "OS: $($runtimeInfo.OS)"

    $installDir = $RuntimesDir
    if (!$Global) {
        $RuntimeFolder = Join-Path $RuntimesDir $($runtimeInfo.RuntimeName)
    }
    else {
        $installDir = $GlobalRuntimesDir
        $RuntimeFolder = Join-Path $GlobalRuntimesDir $($runtimeInfo.RuntimeName)
    }

    _WriteDebug "Destination: $RuntimeFolder"

    if((Test-Path $RuntimeFolder) -and $Force) {
        _WriteOut "Cleaning existing installation..."
        Remove-Item $RuntimeFolder -Recurse -Force
    }

    $installed=""
    if(Test-Path (Join-Path $RuntimesDir $($runtimeInfo.RuntimeName))) {
        $installed = Join-Path $RuntimesDir $($runtimeInfo.RuntimeName)
    }
    if(Test-Path (Join-Path $GlobalRuntimesDir $($runtimeInfo.RuntimeName))) {
        $installed = Join-Path $GlobalRuntimesDir $($runtimeInfo.RuntimeName)
    }
    if($installed -ne "") {
        _WriteOut "'$($runtimeInfo.RuntimeName)' is already installed in $installed."
        if($runtimeInfo.OS -eq "win") {
            dnvm-use $runtimeInfo.Version -Architecture:$runtimeInfo.Architecture -Runtime:$runtimeInfo.Runtime -Persistent:$Persistent -OS:$runtimeInfo.OS
        }
    }
    else {
         
        $Architecture = $runtimeInfo.Architecture
        $Runtime = $runtimeInfo.Runtime
        $OS = $runtimeInfo.OS
        
        $TempFolder = Join-Path $installDir "temp" 
        $UnpackFolder = Join-Path $TempFolder $runtimeFullName
        $DownloadFile = Join-Path $UnpackFolder "$runtimeFullName.nupkg"

        if(Test-Path $UnpackFolder) {
            _WriteDebug "Cleaning temporary directory $UnpackFolder"
            Remove-Item $UnpackFolder -Recurse -Force
        }
        New-Item -Type Directory $UnpackFolder | Out-Null

        if($IsNuPkg) {
            Write-Progress -Activity "Installing runtime" -Status "Copying package" -Id 1
            _WriteDebug "Copying local nupkg $VersionNuPkgOrAlias to $DownloadFile"
            Copy-Item $VersionNuPkgOrAlias $DownloadFile
        } else {
            # Download the package
            Write-Progress -Activity "Installing runtime" -Status "Downloading runtime" -Id 1
            _WriteDebug "Downloading version $($runtimeInfo.Version) to $DownloadFile"

            Download-Package -RuntimeInfo:$runtimeInfo -DownloadUrl:$findPackageResult.DownloadUrl -DestinationFile:$DownloadFile -Proxy:$Proxy -Feed:$selectedFeed
        }

        Write-Progress -Activity "Installing runtime" -Status "Unpacking runtime" -Id 1
        Unpack-Package $DownloadFile $UnpackFolder

        if(Test-Path $RuntimeFolder) {
            # Ensure the runtime hasn't been installed in the time it took to download the package.
            _WriteOut "'$($runtimeInfo.RuntimeName)' is already installed."
        }
        else {
            _WriteOut "Installing to $RuntimeFolder"
            _WriteDebug "Moving package contents to $RuntimeFolder"
            try {
                Move-Item $UnpackFolder $RuntimeFolder
            } catch {
                if(Test-Path $RuntimeFolder) {
                    #Attempt to cleanup the runtime folder if it is there after a fail.
                    Remove-Item $RuntimeFolder -Recurse -Force
                    throw
                }
            }
            #If there is nothing left in the temp folder remove it. There could be other installs happening at the same time as this.
            if(Test-Path $(Join-Path $TempFolder "*")) {
                Remove-Item $TempFolder -Recurse
            }
        }

        if($runtimeInfo.OS -eq "win") {
            dnvm-use $runtimeInfo.Version -Architecture:$runtimeInfo.Architecture -Runtime:$runtimeInfo.Runtime -Persistent:$Persistent -OS:$runtimeInfo.OS
        }
        
        if ($runtimeInfo.Runtime -eq "clr") {
            if (-not $NoNative) {
                if ((Is-Elevated) -or $Ngen) {
                    $runtimeBin = Get-RuntimePath $runtimeInfo.RuntimeName
                    Write-Progress -Activity "Installing runtime" -Status "Generating runtime native images" -Id 1
                    Ngen-Library $runtimeBin $runtimeInfo.Architecture
                }
                else {
                    _WriteOut "Native image generation (ngen) is skipped. Include -Ngen switch to turn on native image generation to improve application startup time."
                }
            }
        }
        elseif ($runtimeInfo.Runtime -eq "coreclr") {
            if ($NoNative -or $runtimeInfo.OS -ne "win") {
                _WriteOut "Skipping native image compilation."
            }
            else {
                _WriteOut "Compiling native images for $($runtimeInfo.RuntimeName) to improve startup performance..."
                Write-Progress -Activity "Installing runtime" -Status "Generating runtime native images" -Id 1
 
                if(Get-Command $CrossGenCommand -ErrorAction SilentlyContinue) {
                    $crossGenCommand = $CrossGenCommand
                } else {
                    $crossGenCommand = $OldCrossGenCommand
                }

                if ($DebugPreference -eq 'SilentlyContinue') {
                    Start-Process $crossGenCommand -Wait -WindowStyle Hidden
                }
                else {
                    Start-Process $crossGenCommand -Wait -NoNewWindow
                }
                _WriteOut "Finished native image compilation."
            }
        }
        else {
            _WriteOut "Unexpected platform: $($runtimeInfo.Runtime). No optimization would be performed on the package installed."
        }
    }

    if($Alias) {
        if($runtimeInfo.OS -eq "win") {
            _WriteDebug "Aliasing installed runtime to '$Alias'"
            dnvm-alias $Alias $runtimeInfo.Version -Architecture:$RuntimeInfo.Architecture -Runtime:$RuntimeInfo.Runtime -OS:$RuntimeInfo.OS
        } else {
            _WriteOut "Unable to set an alias for a non-windows runtime. Installing non-windows runtimes on Windows are meant only for publishing, not running."
        }
    }

    Write-Progress -Status "Done" -Activity "Install complete" -Id 1 -Complete
}

<#
.SYNOPSIS
    Uninstalls a version of the runtime
.PARAMETER VersionOrAlias
    The version to uninstall from the current channel or an alias value to uninstall an alternate
    runtime or architecture flavor of the specified alias.
.PARAMETER Architecture
    The processor architecture of the runtime to uninstall (default: x86)
.PARAMETER Runtime
    The runtime flavor to uninstall (default: clr)
.PARAMETER OS
    The operating system that the runtime targets (default: win)
#>
function dnvm-uninstall {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$VersionOrAlias,

        [Alias("arch")]
        [ValidateSet("", "x86", "x64", "arm")]
        [Parameter(Mandatory=$false)]
        [string]$Architecture = "",

        [Alias("r")]
        [ValidateSet("", "clr", "coreclr", "mono")]
        [Parameter(Mandatory=$false)]
        [string]$Runtime = "",

        [ValidateSet("", "win", "osx", "darwin", "linux")]
        [Parameter(Mandatory=$false)]
        [string]$OS = "")

    $aliasPath = Join-Path $AliasesDir "$VersionOrAlias$AliasExtension"
    
    if(Test-Path $aliasPath) {
        $BaseName = Get-Content $aliasPath
    } else {
        $Version = $VersionOrAlias
        $runtimeInfo = GetRuntimeInfo $Architecture $Runtime $OS $Version
        $BaseName = $runtimeInfo.RuntimeName
    }

    $runtimeFolder=""
    if(Test-Path (Join-Path $RuntimesDir $BaseName)) {
        $runtimeFolder = Join-Path $RuntimesDir $BaseName
    }
    if(Test-Path (Join-Path $GlobalRuntimesDir $BaseName)) {
        $runtimeFolder = Join-Path $GlobalRuntimesDir $BaseName
    }

    if($runtimeFolder -ne "") {
        Remove-Item -literalPath $runtimeFolder -Force -Recurse
        _WriteOut "Removed '$($runtimeFolder)'"
    } else {
        _WriteOut "'$($BaseName)' is not installed"
    }

    $aliases = Get-RuntimeAlias

    $result = @($aliases | Where-Object { $_.Name.EndsWith($BaseName) })
    foreach($alias in $result) {
        dnvm-alias -Delete -Name $alias.Alias
    }
}

<#
.SYNOPSIS
    Adds a runtime to the PATH environment variable for your current shell
.PARAMETER VersionOrAlias
    The version or alias of the runtime to place on the PATH
.PARAMETER Architecture
    The processor architecture of the runtime to place on the PATH (default: x86, or whatever the alias specifies in the case of use-ing an alias)
.PARAMETER Runtime
    The runtime flavor of the runtime to place on the PATH (default: clr, or whatever the alias specifies in the case of use-ing an alias)
.PARAMETER OS
    The operating system that the runtime targets (default: win)
.PARAMETER Persistent
    Make the change persistent across all processes run by the current user
#>
function dnvm-use {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$VersionOrAlias,

        [Alias("arch", "a")]
        [ValidateSet("", "x86", "x64", "arm")]
        [Parameter(Mandatory=$false)]
        [string]$Architecture = "",

        [Alias("r")]
        [ValidateSet("", "clr", "coreclr")]
        [Parameter(Mandatory=$false)]
        [string]$Runtime = "",
        
        [ValidateSet("", "win", "osx", "darwin", "linux")]
        [Parameter(Mandatory=$false)]
        [string]$OS = "",

        [Alias("p")]
        [Parameter(Mandatory=$false)]
        [switch]$Persistent)

    if ($versionOrAlias -eq "none") {
        _WriteOut "Removing all runtimes from process PATH"
        Set-Path (Change-Path $env:Path "" $RuntimeDirs)

        if ($Persistent) {
            _WriteOut "Removing all runtimes from user PATH"
            $userPath = [Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
            $userPath = Change-Path $userPath "" $RuntimeDirs
            [Environment]::SetEnvironmentVariable("Path", $userPath, [System.EnvironmentVariableTarget]::User)
        }
        return;
    }
    
    $runtimeInfo = Get-RuntimeAliasOrRuntimeInfo -Version:$VersionOrAlias -Architecture:$Architecture -Runtime:$Runtime -OS:$OS 
    $runtimeFullName = $runtimeInfo.RuntimeName
    $runtimeBin = Get-RuntimePath $runtimeFullName
    if ($runtimeBin -eq $null) {
        throw "Cannot find $runtimeFullName, do you need to run '$CommandName install $versionOrAlias'?"
    }

    _WriteOut "Adding $runtimeBin to process PATH"
    Set-Path (Change-Path $env:Path $runtimeBin $RuntimeDirs)

    if ($Persistent) {
        _WriteOut "Adding $runtimeBin to user PATH"
        $userPath = [Environment]::GetEnvironmentVariable("Path", [System.EnvironmentVariableTarget]::User)
        $userPath = Change-Path $userPath $runtimeBin $RuntimeDirs
        [Environment]::SetEnvironmentVariable("Path", $userPath, [System.EnvironmentVariableTarget]::User)
    }
}

<#
.SYNOPSIS
    Locates the dnx.exe for the specified version or alias and executes it, providing the remaining arguments to dnx.exe
.PARAMETER VersionOrAlias
    The version of alias of the runtime to execute
.PARAMETER Architecture
    The processor architecture of the runtime to use (default: x86, or whatever the alias specifies in the case of running an alias)
.PARAMETER Runtime
    The runtime flavor of the runtime to use (default: clr, or whatever the alias specifies in the case of running an alias)
.PARAMETER DnxArguments
    The arguments to pass to dnx.exe
#>
function dnvm-run {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$VersionOrAlias,

        [Alias("arch", "a")]
        [ValidateSet("", "x86", "x64", "arm")]
        [Parameter(Mandatory=$false)]
        [string]$Architecture = "",

        [Alias("r")]
        [ValidateSet("", "clr", "coreclr")]
        [Parameter(Mandatory=$false)]
        [string]$Runtime = "",

        [Parameter(Mandatory=$false, Position=1, ValueFromRemainingArguments=$true)]
        [object[]]$DnxArguments)

    $runtimeInfo = Get-RuntimeAliasOrRuntimeInfo -Version:$VersionOrAlias -Runtime:$Runtime -Architecture:$Architecture

    $runtimeBin = Get-RuntimePath $runtimeInfo.RuntimeName
    if ($runtimeBin -eq $null) {
        throw "Cannot find $($runtimeInfo.Name), do you need to run '$CommandName install $versionOrAlias'?"
    }
    $dnxExe = Join-Path $runtimeBin "dnx.exe"
    if(!(Test-Path $dnxExe)) {
        throw "Cannot find a dnx.exe in $runtimeBin, the installation may be corrupt. Try running 'dnvm install $VersionOrAlias -f' to reinstall it"
    }
    _WriteDebug "> $dnxExe $DnxArguments"
    & $dnxExe @DnxArguments
    $Script:ExitCode = $LASTEXITCODE
}

<#
.SYNOPSIS
    Executes the specified command in a sub-shell where the PATH has been augmented to include the specified DNX
.PARAMETER VersionOrAlias
    The version of alias of the runtime to make active in the sub-shell
.PARAMETER Architecture
    The processor architecture of the runtime to use (default: x86, or whatever the alias specifies in the case of exec-ing an alias)
.PARAMETER Runtime
    The runtime flavor of the runtime to use (default: clr, or whatever the alias specifies in the case of exec-ing an alias)
.PARAMETER Command
    The command to execute in the sub-shell
#>
function dnvm-exec {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$VersionOrAlias,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$Command,

        [Alias("arch", "a")]
        [ValidateSet("", "x86", "x64", "arm")]
        [Parameter(Mandatory=$false)]
        [string]$Architecture = "",

        [Alias("r")]
        [ValidateSet("", "clr", "coreclr")]
        [Parameter(Mandatory=$false)]
        [string]$Runtime = "",
        [Parameter(Mandatory=$false, Position=2, ValueFromRemainingArguments=$true)]
        [object[]]$Arguments)

    $runtimeInfo = Get-RuntimeAliasOrRuntimeInfo -Version:$VersionOrAlias -Runtime:$Runtime -Architecture:$Architecture
    $runtimeBin = Get-RuntimePath $runtimeInfo.RuntimeName

    if ($runtimeBin -eq $null) {
        throw "Cannot find $($runtimeInfo.RuntimeName), do you need to run '$CommandName install $versionOrAlias'?"
    }

    $oldPath = $env:PATH
    try {
        $env:PATH = "$runtimeBin;$($env:PATH)"
        & $Command @Arguments
    } finally {
        $Script:ExitCode = $LASTEXITCODE
        $env:PATH = $oldPath
    }
}

<#
.SYNOPSIS
    Installs the version manager into your User profile directory
.PARAMETER SkipUserEnvironmentInstall
    Set this switch to skip configuring the user-level DNX_HOME and PATH environment variables
#>
function dnvm-setup {
    param(
        [switch]$SkipUserEnvironmentInstall)

    $DestinationHome = [Environment]::ExpandEnvironmentVariables("$DefaultUserHome")

    # Install scripts
    $Destination = "$DestinationHome\bin"
    _WriteOut "Installing $CommandFriendlyName to $Destination"

    $ScriptFolder = Split-Path -Parent $ScriptPath

    # Copy script files (if necessary):
    Safe-Filecopy "$CommandName.ps1" $ScriptFolder $Destination
    Safe-Filecopy "$CommandName.cmd" $ScriptFolder $Destination

    # Configure Environment Variables
    # Also, clean old user home values if present
    # We'll be removing any existing homes, both
    $PathsToRemove = @(
        "$DefaultUserHome",
        [Environment]::ExpandEnvironmentVariables($OldUserHome),
        $DestinationHome,
        $OldUserHome)

    # First: PATH
    _WriteOut "Adding $Destination to Process PATH"
    Set-Path (Change-Path $env:PATH $Destination $PathsToRemove)

    if(!$SkipUserEnvironmentInstall) {
        _WriteOut "Adding $Destination to User PATH"
        $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        $userPath = Change-Path $userPath $Destination $PathsToRemove
        [Environment]::SetEnvironmentVariable("PATH", $userPath, "User")
    }

    # Now clean up the HomeEnvVar if currently set; script installed to default location.
    Clean-HomeEnv($SkipUserEnvironmentInstall)
}

function Check-Runtimes(){
    $runtimesInstall = $false;
    foreach($runtimeHomeDir in $RuntimeHomes) {
        if (Test-Path "$runtimeHomeDir\runtimes") {
            if(Test-Path "$runtimeHomeDir\runtimes\$RuntimePackageName-*"){
                $runtimesInstall = $true;
                break;
            }
        }
    }
    
    if (-not $runtimesInstall){
        $title = "Getting started"
        $message = "It looks like you don't have any runtimes installed. Do you want us to install a $RuntimeShortFriendlyName to get you started?"
    
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Install the latest runtime for you"
    
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Do not install the latest runtime and continue"
    
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    
        $result = $host.ui.PromptForChoice($title, $message, $options, 0)
        
        if($result -eq 0){
            dnvm-upgrade
        }
    }
}

### The main "entry point"

# Check for old DNX_HOME values
if($UnencodedHomes -contains $OldUserHome) {
    _WriteOut -ForegroundColor Yellow "WARNING: Found '$OldUserHome' in your $HomeEnvVar value. This folder has been deprecated."
    if($UnencodedHomes -notcontains $DefaultUserHome) {
        _WriteOut -ForegroundColor Yellow "WARNING: Didn't find '$DefaultUserHome' in your $HomeEnvVar value. You should run '$CommandName setup' to upgrade."
    }
}

# Check for old KRE_HOME variable
if(Test-Path env:\KRE_HOME) {
    _WriteOut -ForegroundColor Yellow "WARNING: Found a KRE_HOME environment variable. This variable has been deprecated and should be removed, or it may interfere with DNVM and the .NET Execution environment"
}

# Read arguments

$cmd = $args[0]

if($args.Length -gt 1) {
    $cmdargs = @($args[1..($args.Length-1)])
} else {
    $cmdargs = @()
}

# Can't add this as script-level arguments because they mask '-a' arguments in subcommands!
# So we manually parse them :)
if($cmdargs -icontains "-amd64") {
    $CompatArch = "x64"
    _WriteOut "The -amd64 switch has been deprecated. Use the '-arch x64' parameter instead"
} elseif($cmdargs -icontains "-x86") {
    $CompatArch = "x86"
    _WriteOut "The -x86 switch has been deprecated. Use the '-arch x86' parameter instead"
} elseif($cmdargs -icontains "-x64") {
    $CompatArch = "x64"
    _WriteOut "The -x64 switch has been deprecated. Use the '-arch x64' parameter instead"
}
$cmdargs = @($cmdargs | Where-Object { @("-amd64", "-x86", "-x64") -notcontains $_ })

if(!$cmd) {
    Check-Runtimes
    $cmd = "help"
    $Script:ExitCode = $ExitCodes.InvalidArguments
}

# Check for the command and run it
try {
    if(Get-Command -Name "$CommandPrefix$cmd" -ErrorAction SilentlyContinue) {
        _WriteDebug "& dnvm-$cmd $cmdargs"
        Invoke-Command ([ScriptBlock]::Create("dnvm-$cmd $cmdargs"))
    }
    else {
        _WriteOut "Unknown command: '$cmd'"
        dnvm-help
        $Script:ExitCode = $ExitCodes.UnknownCommand
    }
} catch {
    throw
    if(!$Script:ExitCode) { $Script:ExitCode = $ExitCodes.OtherError }
}

_WriteDebug "=== End $CommandName (Exit Code $Script:ExitCode) ==="
_WriteDebug ""
exit $Script:ExitCode

# SIG # Begin signature block
# MIIkCQYJKoZIhvcNAQcCoIIj+jCCI/YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCByeACx9YutuTq/
# ls/hTzkJSiEtMoL8AQxvjZXQgGlWx6CCDZIwggYQMIID+KADAgECAhMzAAAAOI0j
# bRYnoybgAAAAAAA4MA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTQxMDAxMTgxMTE2WhcNMTYwMTAxMTgxMTE2WjCBgzEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjENMAsGA1UECxMETU9Q
# UjEeMBwGA1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAwt7Wz+K3fxFl/7NjqfNyufEk61+kHLJEWetvnPtw
# 22VpmquQMV7/3itkEfXtbOkAIYLDkMyCGaPjmWNlir3T1fsgo+AZf7iNPGr+yBKN
# 5dM5701OPoaWTBGxEYSbJ5iIOy3UfRjzBeCtSwQ+Q3UZ5kbEjJ3bidgkh770Rye/
# bY3ceLnDZaFvN+q8caadrI6PjYiRfqg3JdmBJKmI9GNG6rsgyQEv2I4M2dnt4Db7
# ZGhN/EIvkSCpCJooSkeo8P7Zsnr92Og4AbyBRas66Boq3TmDPwfb2OGP/DksNp4B
# n+9od8h4bz74IP+WGhC+8arQYZ6omoS/Pq6vygpZ5Y2LBQIDAQABo4IBfzCCAXsw
# HwYDVR0lBBgwFgYIKwYBBQUHAwMGCisGAQQBgjdMCAEwHQYDVR0OBBYEFMbxyhgS
# CySlRfWC5HUl0C8w12JzMFEGA1UdEQRKMEikRjBEMQ0wCwYDVQQLEwRNT1BSMTMw
# MQYDVQQFEyozMTY0MitjMjJjOTkzNi1iM2M3LTQyNzEtYTRiZC1mZTAzZmE3MmMz
# ZjAwHwYDVR0jBBgwFoAUSG5k5VAF04KqFzc3IrVtqMp1ApUwVAYDVR0fBE0wSzBJ
# oEegRYZDaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljQ29k
# U2lnUENBMjAxMV8yMDExLTA3LTA4LmNybDBhBggrBgEFBQcBAQRVMFMwUQYIKwYB
# BQUHMAKGRWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWlj
# Q29kU2lnUENBMjAxMV8yMDExLTA3LTA4LmNydDAMBgNVHRMBAf8EAjAAMA0GCSqG
# SIb3DQEBCwUAA4ICAQCecm6ourY1Go2EsDqVN+I0zXvsz1Pk7qvGGDEWM3tPIv6T
# dVZHTXRrmYdcLnSIcKVGb7ScG5hZEk00vtDcdbNdDDPW2AX2NRt+iUjB5YmlLTo3
# J0ce7mjTaFpGoqyF+//Q6OjVYFXnRGtNz73epdy71XqL0+NIx0Z7dZhz+cPI7IgQ
# C/cqLRN4Eo/+a6iYXhxJzjqmNJZi2+7m4wzZG2PH+hhh7LkACKvkzHwSpbamvWVg
# Dh0zWTjfFuEyXH7QexIHgbR+uKld20T/ZkyeQCapTP5OiT+W0WzF2K7LJmbhv2Xj
# 97tj+qhtKSodJ8pOJ8q28Uzq5qdtCrCRLsOEfXKAsfg+DmDZzLsbgJBPixGIXncI
# u+OKq39vCT4rrGfBR+2yqF16PLAF9WCK1UbwVlzypyuwLhEWr+KR0t8orebVlT/4
# uPVr/wLnudvNvP2zQMBxrkadjG7k9gVd7O4AJ4PIRnvmwjrh7xy796E3RuWGq5eu
# dXp27p5LOwbKH6hcrI0VOSHmveHCd5mh9yTx2TgeTAv57v+RbbSKSheIKGPYUGNc
# 56r7VYvEQYM3A0ABcGOfuLD5aEdfonKLCVMOP7uNQqATOUvCQYMvMPhbJvgfuS1O
# eQy77Hpdnzdq2Uitdp0v6b5sNlga1ZL87N/zsV4yFKkTE/Upk/XJOBbXNedrODCC
# B3owggVioAMCAQICCmEOkNIAAAAAAAMwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDExMB4XDTExMDcwODIwNTkw
# OVoXDTI2MDcwODIxMDkwOVowfjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAx
# MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKvw+nIQHC6t2G6qghBN
# NLrytlghn0IbKmvpWlCquAY4GgRJun/DDB7dN2vGEtgL8DjCmQawyDnVARQxQtOJ
# DXlkh36UYCRsr55JnOloXtLfm1OyCizDr9mpK656Ca/XllnKYBoF6WZ26DJSJhIv
# 56sIUM+zRLdd2MQuA3WraPPLbfM6XKEW9Ea64DhkrG5kNXimoGMPLdNAk/jj3gcN
# 1Vx5pUkp5w2+oBN3vpQ97/vjK1oQH01WKKJ6cuASOrdJXtjt7UORg9l7snuGG9k+
# sYxd6IlPhBryoS9Z5JA7La4zWMW3Pv4y07MDPbGyr5I4ftKdgCz1TlaRITUlwzlu
# ZH9TupwPrRkjhMv0ugOGjfdf8NBSv4yUh7zAIXQlXxgotswnKDglmDlKNs98sZKu
# HCOnqWbsYR9q4ShJnV+I4iVd0yFLPlLEtVc/JAPw0XpbL9Uj43BdD1FGd7P4AOG8
# rAKCX9vAFbO9G9RVS+c5oQ/pI0m8GLhEfEXkwcNyeuBy5yTfv0aZxe/CHFfbg43s
# TUkwp6uO3+xbn6/83bBm4sGXgXvt1u1L50kppxMopqd9Z4DmimJ4X7IvhNdXnFy/
# dygo8e1twyiPLI9AN0/B4YVEicQJTMXUpUMvdJX3bvh4IFgsE11glZo+TzOE2rCI
# F96eTvSWsLxGoGyY0uDWiIwLAgMBAAGjggHtMIIB6TAQBgkrBgEEAYI3FQEEAwIB
# ADAdBgNVHQ4EFgQUSG5k5VAF04KqFzc3IrVtqMp1ApUwGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0j
# BBgwFoAUci06AjGQQ7kUBU7h6qfHMdEjiTQwWgYDVR0fBFMwUTBPoE2gS4ZJaHR0
# cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2Vy
# QXV0MjAxMV8yMDExXzAzXzIyLmNybDBeBggrBgEFBQcBAQRSMFAwTgYIKwYBBQUH
# MAKGQmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0MjAxMV8yMDExXzAzXzIyLmNydDCBnwYDVR0gBIGXMIGUMIGRBgkrBgEEAYI3
# LgMwgYMwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvZG9jcy9wcmltYXJ5Y3BzLmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBh
# AGwAXwBwAG8AbABpAGMAeQBfAHMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG
# 9w0BAQsFAAOCAgEAZ/KGpZjgVHkaLtPYdGcimwuWEeFjkplCln3SeQyQwWVfLiw+
# +MNy0W2D/r4/6ArKO79HqaPzadtjvyI1pZddZYSQfYtGUFXYDJJ80hpLHPM8QotS
# 0LD9a+M+By4pm+Y9G6XUtR13lDni6WTJRD14eiPzE32mkHSDjfTLJgJGKsKKELuk
# qQUMm+1o+mgulaAqPyprWEljHwlpblqYluSD9MCP80Yr3vw70L01724lruWvJ+3Q
# 3fMOr5kol5hNDj0L8giJ1h/DMhji8MUtzluetEk5CsYKwsatruWy2dsViFFFWDgy
# cScaf7H0J/jeLDogaZiyWYlobm+nt3TDQAUGpgEqKD6CPxNNZgvAs0314Y9/HG8V
# fUWnduVAKmWjw11SYobDHWM2l4bf2vP48hahmifhzaWX0O5dY0HjWwechz4GdwbR
# BrF1HxS+YWG18NzGGwS+30HHDiju3mUv7Jf2oVyW2ADWoUa9WfOXpQlLSBCZgB/Q
# ACnFsZulP0V3HjXG0qKin3p6IvpIlR+r+0cjgPWe+L9rt0uX4ut1eBrs6jeZeRhL
# /9azI2h15q/6/IvrC4DqaTuv/DDtBEyO3991bWORPdGdVk5Pv4BXIqF4ETIheu9B
# CrE/+6jMpF3BoYibV3FWTkhFwELJm3ZbCoBIa/15n8G9bW1qyVJzEw16UM0xghXN
# MIIVyQIBATCBlTB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExAhMzAAAA
# OI0jbRYnoybgAAAAAAA4MA0GCWCGSAFlAwQCAQUAoIG6MBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqG
# SIb3DQEJBDEiBCB3z50tiUvPa0AhMCX0l/Ot825Ob3FfymK5FOFGe7F1UjBOBgor
# BgEEAYI3AgEMMUAwPqAkgCIATQBpAGMAcgBvAHMAbwBmAHQAIABBAFMAUAAuAE4A
# RQBUoRaAFGh0dHA6Ly93d3cuYXNwLm5ldC8gMA0GCSqGSIb3DQEBAQUABIIBAAfj
# M8Zw8p4N3HAYQ+WoqNPwd/ansDCAXrf/fbLt4ErEJ2FPz6QNrJC3iYj7Fmzq8WX1
# Rq9VeU+a5vpQgaD+Zfs+BIpJ41/s2M5951Ht/eUNNQJsqZ1R6ceS15qpUJV/DRUT
# JU2yA8LsZVTVBQWmkx+CM46Vp4A4RitEBPc5fD/xNUdTZGAik/2mXsb89ff9I6O3
# Az3Mbh4AMfwj60lZCch/mTCb2fQEZSM3PJV34E7TjK8Hlma4i4/4rdRENjg7WE3t
# 7IYJHInn90YnZnO0c9fGnA6EiOjAtmK1tl2vQY9w8z5r4Df0UQxqBt1Dx17thJNG
# eHDdH4/Z4YKnCctm5u+hghNLMIITRwYKKwYBBAGCNwMDATGCEzcwghMzBgkqhkiG
# 9w0BBwKgghMkMIITIAIBAzEPMA0GCWCGSAFlAwQCAQUAMIIBOwYLKoZIhvcNAQkQ
# AQSgggEqBIIBJjCCASICAQEGCisGAQQBhFkKAwEwMTANBglghkgBZQMEAgEFAAQg
# Rwq5syRQsP9Kjb6r4HaCDdipry44lK4F5sbgb3Qda2gCBlX5oY37ahgRMjAxNTEw
# MTAwODAzNTkuNFowBwIBAYACAfSggbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBo
# ZXIgRFNFIEVTTjpDMEY0LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZaCCDtAwggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0G
# CSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3Jp
# dHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3
# PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMw
# VyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijG
# GvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/
# 9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9
# pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGCNxUB
# BAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8G
# A1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeG
# RWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUH
# MAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2Vy
# QXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQBgjcu
# AzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9k
# b2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwA
# XwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0B
# AQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LF
# Zslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/XPle
# FzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6
# AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHOmWaQ
# jP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU9Mal
# CpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6YacR
# y5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdlR3jo
# +KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rIDVWZ
# eodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMR
# ZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/
# XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRIwggTaMIID
# wqADAgECAhMzAAAAUpo7I6rcf7RvAAAAAABSMA0GCSqGSIb3DQEBCwUAMHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE1MDMyMDE3MzIyNloXDTE2MDYy
# MDE3MzIyNlowgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# DTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjpDMEY0LTMw
# ODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOLvsXs51YcPijzAWkdxnm+V
# jjFEYge/o1AtSNy0sAYcUgmZrBbN/kNd5Srb0zeC0UyhTGIZYqVQI/Y1CxhpJc/L
# GfrExbJcVll/zPY/T+GCFfHgWu3JmYJ7zcZ6r7iGFIo5UY3rZFUx/FW65QzJ//v+
# JnStSjLnHR5WijiQ75TrIFfyd+gAcxuHTr8rsC+tsLNGkkppAM0g7c8XaOjuHler
# P3yIFtUWl46h8nxel0nCRCd3V2LFtZI2/SI1wmbEgdtYa51qqgTDNAf9gpsGScVi
# a60ioHraa/cIOc8XHsOD69O6+euItf93ejImv9gqO0g1q7JyBsTDnYFwri+dA18C
# AwEAAaOCARswggEXMB0GA1UdDgQWBBQxFRmGUGiyTk5Nmq3QAcbiU8SD/TAfBgNV
# HSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVo
# dHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1T
# dGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAC
# hj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBD
# QV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMA0GCSqGSIb3DQEBCwUAA4IBAQAM82+vetzMQYRHLKf2aET8YLq0D1grM61R
# 7UYUQnIwMyEXabVJS+9dT+/nnc5Vb7/ypczj0/TGnKp4D7chbGCAB9YXuaw2Hth2
# TRK5IOUmfjodsnVS3syFjCtLedp5n1fcDfEFg3dsIC6BSjFSoaZJeqkMUzzzr5KI
# QQhpNfMtvdcBhq6HV2kHVJCRlT1TF/w2CfkazBzS1SBJxDY0zY94HlPtH/RyQpWF
# 5B3ydI7X7ga1gz7gH0Wa/gNmx48KRchzuPL8ssbaH9f7TmMY1BlPnTN4GAJqynuG
# nrYFjUMtqf2RkOVP87QlDPBrkK/gOLEmDxmX7OqlvX9RMQKmLAU2oYIDeTCCAmEC
# AQEwgeOhgbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjpDMEY0
# LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2Vydmlj
# ZaIlCgEBMAkGBSsOAwIaBQADFQB6NOnIZOKf7B65PSPqxHeDbDDPvKCBwjCBv6SB
# vDCBuTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjENMAsGA1UE
# CxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBOVFMgRVNOOjU3RjYtQzFFMC01NTRD
# MSswKQYDVQQDEyJNaWNyb3NvZnQgVGltZSBTb3VyY2UgTWFzdGVyIENsb2NrMA0G
# CSqGSIb3DQEBBQUAAgUA2cLNuTAiGA8yMDE1MTAwOTIzMzUyMVoYDzIwMTUxMDEw
# MjMzNTIxWjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDZws25AgEAMAoCAQACAggi
# AgH/MAcCAQACAhiZMAoCBQDZxB85AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisG
# AQQBhFkKAwGgCjAIAgEAAgMW42ChCjAIAgEAAgMHoSAwDQYJKoZIhvcNAQEFBQAD
# ggEBAJWg6ueIgS+Dnd+xXcOxvyF7pIwmjA93W0WRQT7YP1auE2XX6qW77XuP9P6E
# xMSRGzbDgo5YdjxFWxAanFOJ9lJsdWGAaPPrGo5b4rWwd/4iRLPmj1clanZ1MOPA
# zyYgLkANNq+f7NMXpkny2dhFogLqTI1k1JuqHoXNrhM9fKFOgf9UmvXoH8aocuCz
# DXbOvhBxzmPB1DOrA2hry8gHege2Eh1DaEvuzim+gDoZrvx/0eCnWyZnPlLRbMsG
# BORq9qk9HHZ2tzS4Cxcqacm4ZIEXXgZIZw+8QzqNQLfcig73qdyZ3UvIHBdLsBgX
# 07baA4rYib/PY3MOF1qxdISdHn4xggL1MIIC8QIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAFKaOyOq3H+0bwAAAAAAUjANBglghkgBZQME
# AgEFAKCCATIwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCB4BBlRFV0lRcEY3BmljKy9K8HIpXu5nIHkuzlrQfHwJTCB4gYLKoZIhvcN
# AQkQAgwxgdIwgc8wgcwwgbEEFHo06chk4p/sHrk9I+rEd4NsMM+8MIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAABSmjsjqtx/tG8AAAAA
# AFIwFgQU1KW7+xMV6mNLacIaTQEN6LWjGj4wDQYJKoZIhvcNAQELBQAEggEAhO1U
# NLYXd8lrtovcgCU4PX0u1FI3oLL2PLJ9s1yzrtuCBfjTR62yIIg216typYcMnO6C
# 78h0UDSMrJkjQ7k6JXKbq81kC1vo1K/SzJ2IZ/2GryLi0JnjXz4N1mO7chmp0EMO
# om7YTiBNuIA7S4D0xPYTTT0mvp/JVZ0taa+eyqUIx/dZM18+aUbHn9KhqJj11C/a
# ov4h30oVWaJE4MzOI0T3rHcKiVLYcaZmQIRiNXcMOZFZmScokLq6vUZLAQkDKYe2
# PyRVxd2SM4vvccRpzAR/Y/mVVySzgpQhy0HFM0SE0+20CDtfieRPpuF/v4gBwvsG
# 1kvafPdw+wdiT2O+wQ==
# SIG # End signature block
