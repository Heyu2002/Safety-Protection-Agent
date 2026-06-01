param(
    [string]$BaseUrl = "https://localhost:8443/benchmark",
    [string]$CasesPath = "tests\evals\owasp-benchmark-regression-cases.json",
    [string]$OutputDir = "target\owasp-benchmark-score-spa-regression",
    [string]$SpaExe = "",
    [int]$MaxTokens = 0,
    [ValidateSet("auto", "on", "off")]
    [string]$ReportOutput = "off",
    [switch]$SkipHealthCheck,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$scoreScript = Join-Path $scriptDir "eval-owasp-benchmark-score.ps1"

$argsForScore = @{
    BaseUrl = $BaseUrl
    CasesPath = $CasesPath
    OutputDir = $OutputDir
    Runner = "spa"
    Limit = 0
    ReportOutput = $ReportOutput
}

if ($SpaExe) {
    $argsForScore.SpaExe = $SpaExe
}
if ($MaxTokens -gt 0) {
    $argsForScore.MaxTokens = $MaxTokens
}
if ($SkipHealthCheck) {
    $argsForScore.SkipHealthCheck = $true
}
if ($DryRun) {
    $argsForScore.DryRun = $true
}

& $scoreScript @argsForScore
