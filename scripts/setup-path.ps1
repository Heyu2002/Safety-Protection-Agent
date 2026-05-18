param(
    [switch]$Quiet
)

$ErrorActionPreference = "Stop"

$cargoBin = Join-Path $env:USERPROFILE ".cargo\bin"

if (-not (Test-Path -LiteralPath $cargoBin)) {
    New-Item -ItemType Directory -Force -Path $cargoBin | Out-Null
}

function Split-PathList {
    param([string]$PathValue)

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return @()
    }

    return $PathValue.Split(';', [System.StringSplitOptions]::RemoveEmptyEntries) |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_.Length -gt 0 }
}

function Contains-PathEntry {
    param(
        [string[]]$Entries,
        [string]$Needle
    )

    foreach ($entry in $Entries) {
        if ($entry.TrimEnd('\') -ieq $Needle.TrimEnd('\')) {
            return $true
        }
    }

    return $false
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$userEntries = @(Split-PathList $userPath)
$updatedUserPath = $false

if (-not (Contains-PathEntry $userEntries $cargoBin)) {
    $newUserEntries = $userEntries + $cargoBin
    [Environment]::SetEnvironmentVariable("Path", ($newUserEntries -join ';'), "User")
    $updatedUserPath = $true
}

$processEntries = @(Split-PathList $env:Path)
if (-not (Contains-PathEntry $processEntries $cargoBin)) {
    $env:Path = (($processEntries + $cargoBin) -join ';')
}

if (-not $Quiet) {
    if ($updatedUserPath) {
        Write-Host "Added to user PATH: $cargoBin"
        Write-Host "Open a new terminal to use the updated PATH everywhere."
    } else {
        Write-Host "User PATH already contains: $cargoBin"
    }

    Write-Host "Current session can use Cargo binaries now."
}
