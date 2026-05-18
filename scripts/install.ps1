param(
    [switch]$SkipPath
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

if (-not $SkipPath) {
    & (Join-Path $scriptDir "setup-path.ps1") -Quiet
}

Push-Location $repoRoot
try {
    cargo install --path . --force
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Install complete. Start the interactive CLI with:"
Write-Host "  spa"
