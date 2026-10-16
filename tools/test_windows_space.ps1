# Requires an elevated Windows PowerShell/PowerShell session and Storage cmdlets.
# Creates and fills only a new 32 MiB VHD; never accepts an existing disk/volume.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $TestExecutable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This isolated VHD test requires an administrator session. Nothing was created.'
}

$executable = (Resolve-Path -LiteralPath $TestExecutable).Path
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$buildRoot = Join-Path $workspace 'build'
$testRoot = Join-Path $buildRoot ('windows-space-' + [guid]::NewGuid().ToString('N'))
$imagePath = Join-Path $testRoot 'fixture.vhd'
$scriptPath = Join-Path $testRoot 'create.txt'
$diskpartEncoding = [Text.Encoding]::GetEncoding(
    [Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
if ($diskpartEncoding.GetString($diskpartEncoding.GetBytes($imagePath)) -cne $imagePath) {
    throw 'The diskpart script path cannot be represented in the system ANSI code page.'
}

function Get-FixtureDisk {
    $image = Get-DiskImage -ImagePath $imagePath
    if (-not $image.Attached -or
        -not [string]::Equals([IO.Path]::GetFullPath($image.ImagePath), $imagePath,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Test image identity/attachment check failed.'
    }
    $disks = @($image | Get-Disk)
    if ($disks.Count -ne 1) { throw 'Expected exactly one disk for the new VHD.' }
    $disk = $disks[0]
    if ([string]$disk.BusType -ne 'File Backed Virtual' -or $disk.Size -ne 32MB -or
        $disk.IsBoot -or $disk.IsSystem) {
        throw 'Refusing to modify a disk that is not the bounded test VHD.'
    }
    return $disk
}

if (Test-Path -LiteralPath $testRoot) { throw 'Test directory already exists.' }
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    # No disk-selection, attach or format commands are passed to diskpart.
    # Its default behavior stops on an error (no NOERR).
    [IO.File]::WriteAllText($scriptPath,
        ('create vdisk file="{0}" maximum=32 type=expandable' -f $imagePath) + "`r`n",
        $diskpartEncoding)
    & diskpart.exe /s $scriptPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $imagePath)) {
        throw 'Creating the fresh test VHD failed.'
    }
    Mount-DiskImage -ImagePath $imagePath -StorageType VHD -Access ReadWrite -NoDriveLetter |
        Out-Null
    $disk = Get-FixtureDisk
    if ([string]$disk.PartitionStyle -ne 'RAW') { throw 'New test disk is not RAW.' }
    Initialize-Disk -InputObject $disk -PartitionStyle MBR | Out-Null
    $disk = Get-FixtureDisk
    $partition = New-Partition -InputObject $disk -UseMaximumSize -AssignDriveLetter
    $disk = Get-FixtureDisk
    if ($partition.DiskNumber -ne $disk.Number -or -not $partition.DriveLetter) {
        throw 'Test partition is not on the new VHD.'
    }
    Format-Volume -Partition $partition -FileSystem NTFS -AllocationUnitSize 4096 `
        -NewFileSystemLabel 'FIXER_SPACE_TEST' -Force -Confirm:$false | Out-Null
    $fixtureRoot = '{0}:\fixture' -f $partition.DriveLetter
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    & $executable --windows-space $fixtureRoot
    if ($LASTEXITCODE -ne 0) { throw "Windows disk-full tests failed: $LASTEXITCODE" }
}
finally {
    # Never delete the backing file while Windows still has the image attached.
    if (Test-Path -LiteralPath $imagePath) {
        $image = Get-DiskImage -ImagePath $imagePath
        if ($image.Attached) { Dismount-DiskImage -ImagePath $imagePath | Out-Null }
        if ((Get-DiskImage -ImagePath $imagePath).Attached) {
            throw "Test image remains attached; retained at $imagePath"
        }
    }
    $resolvedRoot = [IO.Path]::GetFullPath($testRoot)
    if (-not $resolvedRoot.StartsWith($buildRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolvedRoot) -notmatch '^windows-space-[0-9a-f]{32}$') {
        throw 'Refusing cleanup outside the unique test directory.'
    }
    Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
}
