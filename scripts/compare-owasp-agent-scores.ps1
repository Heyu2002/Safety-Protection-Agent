param(
    [string[]]$SpaScorePaths = @(),
    [string[]]$CodexScorePaths = @(),
    [string]$ExpectedResultsCsv = "",
    [int]$TotalBenchmarkCases = 0,
    [string]$OutputDir = "target\owasp-benchmark-agent-comparison"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Get-ExpectedCaseCount([string]$Path) {
    if (-not $Path) {
        return 0
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "ExpectedResultsCsv not found: $Path"
    }

    $lines = Get-Content -LiteralPath $Path
    if ($lines.Count -eq 0) {
        return 0
    }
    $lines[0] = $lines[0].TrimStart([char]0xFEFF)
    if ($lines[0].StartsWith("#")) {
        $lines[0] = $lines[0].TrimStart("#").TrimStart()
    }
    return @($lines | ConvertFrom-Csv).Count
}

function Split-PathArguments([string[]]$Values) {
    @($Values | ForEach-Object { "$_".Split(",") } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
}

function Read-ScoreResults([string[]]$Paths, [string]$RunnerName) {
    $Paths = Split-PathArguments $Paths
    $results = @()
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "$RunnerName score path not found: $path"
        }
        $score = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        foreach ($result in @($score.results)) {
            $result | Add-Member -NotePropertyName score_path -NotePropertyValue $path -Force
            $results += $result
        }
    }

    $deduped = @()
    foreach ($group in @($results | Group-Object id)) {
        if ($group.Count -gt 1) {
            Write-Warning "$RunnerName has duplicate result for $($group.Name); using the last one from the input order."
        }
        $deduped += $group.Group[-1]
    }

    return @($deduped | Sort-Object id)
}

function Convert-ValueToBool($Value) {
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [bool]) {
        return $Value
    }
    $normalized = "$Value".Trim().ToLowerInvariant()
    if ($normalized -in @("true", "1", "yes", "y")) {
        return $true
    }
    if ($normalized -in @("false", "0", "no", "n")) {
        return $false
    }
    return $null
}

function New-Summary([string]$RunnerName, [object[]]$Results, [int]$AllCaseCount) {
    $total = @($Results).Count
    $tp = @($Results | Where-Object { $_.outcome -eq "TP" }).Count
    $fp = @($Results | Where-Object { $_.outcome -eq "FP" }).Count
    $tn = @($Results | Where-Object { $_.outcome -eq "TN" }).Count
    $fn = @($Results | Where-Object { $_.outcome -eq "FN" }).Count
    $inconclusive = @($Results | Where-Object { $_.outcome -eq "inconclusive" }).Count
    $parseErrors = @($Results | Where-Object { $_.outcome -eq "parse_error" }).Count
    $executionErrors = @($Results | Where-Object { $_.outcome -eq "execution_error" }).Count
    $decided = $tp + $fp + $tn + $fn
    $correct = $tp + $tn

    $totalSeconds = 0.0
    if ($total -gt 0) {
        $measured = $Results | Measure-Object seconds -Sum
        if ($null -ne $measured.Sum) {
            $totalSeconds = [double]$measured.Sum
        }
    }

    $avgSeconds = $null
    if ($total -gt 0) {
        $avgSeconds = [math]::Round($totalSeconds / $total, 1)
    }

    $estimatedFullHours = $null
    if ($AllCaseCount -gt 0 -and $null -ne $avgSeconds) {
        $estimatedFullHours = [math]::Round(($avgSeconds * $AllCaseCount) / 3600, 1)
    }

    $precision = $null
    if (($tp + $fp) -gt 0) {
        $precision = [math]::Round($tp / ($tp + $fp), 4)
    }
    $recall = $null
    if (($tp + $fn) -gt 0) {
        $recall = [math]::Round($tp / ($tp + $fn), 4)
    }
    $f1 = $null
    if ($null -ne $precision -and $null -ne $recall -and ($precision + $recall) -gt 0) {
        $f1 = [math]::Round((2 * $precision * $recall) / ($precision + $recall), 4)
    }

    [pscustomobject]@{
        runner = $RunnerName
        total = $total
        decided = $decided
        correct = $correct
        TP = $tp
        FP = $fp
        TN = $tn
        FN = $fn
        inconclusive = $inconclusive
        parse_error = $parseErrors
        execution_error = $executionErrors
        strict_accuracy = if ($total -gt 0) { [math]::Round($correct / $total, 4) } else { $null }
        decided_accuracy = if ($decided -gt 0) { [math]::Round($correct / $decided, 4) } else { $null }
        precision = $precision
        recall = $recall
        f1 = $f1
        total_seconds = [math]::Round($totalSeconds, 1)
        avg_seconds = $avgSeconds
        estimated_full_hours = $estimatedFullHours
    }
}

function New-MarkdownReport($Comparison) {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# OWASP Benchmark Agent Comparison")
    $lines.Add("")
    $lines.Add("- Benchmark cases in truth set: $($Comparison.total_benchmark_cases)")
    $lines.Add("- Compared common cases: $($Comparison.common_case_count)")
    $lines.Add("- Generated at: $($Comparison.generated_at)")
    $lines.Add("")
    $lines.Add("## Summary")
    $lines.Add("")
    $lines.Add("| Agent | Cases | Correct | TP | FP | TN | FN | Inconclusive | Accuracy | Recall | Avg seconds/case | Estimated full hours |")
    $lines.Add("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    foreach ($summary in @($Comparison.spa, $Comparison.codex)) {
        $lines.Add("| $($summary.runner) | $($summary.total) | $($summary.correct) | $($summary.TP) | $($summary.FP) | $($summary.TN) | $($summary.FN) | $($summary.inconclusive) | $($summary.strict_accuracy) | $($summary.recall) | $($summary.avg_seconds) | $($summary.estimated_full_hours) |")
    }
    $lines.Add("")
    $lines.Add("## Per Case")
    $lines.Add("")
    $lines.Add("| Case | Category | Expected | SPA verdict | SPA outcome | SPA seconds | Codex verdict | Codex outcome | Codex seconds |")
    $lines.Add("| --- | --- | --- | --- | --- | ---: | --- | --- | ---: |")
    foreach ($row in @($Comparison.per_case)) {
        $lines.Add("| $($row.id) | $($row.category) | $($row.expected_vulnerable) | $($row.spa_verdict) | $($row.spa_outcome) | $($row.spa_seconds) | $($row.codex_verdict) | $($row.codex_outcome) | $($row.codex_seconds) |")
    }

    return ($lines -join [Environment]::NewLine)
}

$SpaScorePaths = Split-PathArguments $SpaScorePaths
$CodexScorePaths = Split-PathArguments $CodexScorePaths

if ($SpaScorePaths.Count -eq 0) {
    throw "Provide at least one -SpaScorePaths value."
}
if ($CodexScorePaths.Count -eq 0) {
    throw "Provide at least one -CodexScorePaths value."
}

if ($TotalBenchmarkCases -le 0) {
    $TotalBenchmarkCases = Get-ExpectedCaseCount $ExpectedResultsCsv
}

$spaResults = Read-ScoreResults $SpaScorePaths "spa"
$codexResults = Read-ScoreResults $CodexScorePaths "codex"

$spaById = @{}
foreach ($result in $spaResults) {
    $spaById[$result.id] = $result
}
$codexById = @{}
foreach ($result in $codexResults) {
    $codexById[$result.id] = $result
}

$caseIds = @($spaById.Keys | Where-Object { $codexById.ContainsKey($_) } | Sort-Object)
$perCase = @()
foreach ($id in $caseIds) {
    $spa = $spaById[$id]
    $codex = $codexById[$id]
    $expected = Convert-ValueToBool $spa.expected_vulnerable
    if ($null -eq $expected) {
        $expected = Convert-ValueToBool $codex.expected_vulnerable
    }
    $perCase += [pscustomobject]@{
        id = $id
        category = if ($spa.category) { $spa.category } else { $codex.category }
        cwe = if ($spa.cwe) { $spa.cwe } else { $codex.cwe }
        expected_vulnerable = $expected
        spa_verdict = $spa.verdict
        spa_outcome = $spa.outcome
        spa_seconds = $spa.seconds
        spa_score_path = $spa.score_path
        codex_verdict = $codex.verdict
        codex_outcome = $codex.outcome
        codex_seconds = $codex.seconds
        codex_score_path = $codex.score_path
    }
}

$comparison = [pscustomobject]@{
    generated_at = (Get-Date).ToString("o")
    total_benchmark_cases = $TotalBenchmarkCases
    spa_score_paths = $SpaScorePaths
    codex_score_paths = $CodexScorePaths
    common_case_count = @($perCase).Count
    spa = New-Summary "spa" $spaResults $TotalBenchmarkCases
    codex = New-Summary "codex" $codexResults $TotalBenchmarkCases
    per_case = $perCase
}

New-Directory $OutputDir
$jsonPath = Join-Path $OutputDir "comparison.json"
$csvPath = Join-Path $OutputDir "comparison.csv"
$markdownPath = Join-Path $OutputDir "comparison.md"

$comparison | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
$perCase | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
New-MarkdownReport $comparison | Set-Content -LiteralPath $markdownPath -Encoding UTF8

Write-Host "Agent comparison complete."
Write-Host "JSON: $jsonPath"
Write-Host "CSV: $csvPath"
Write-Host "Markdown: $markdownPath"
$comparison.spa | Format-List
$comparison.codex | Format-List
