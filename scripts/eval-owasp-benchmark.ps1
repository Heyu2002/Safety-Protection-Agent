param(
    [string]$BaseUrl = "https://localhost:8443/benchmark",
    [string]$ExpectedResultsCsv = "",
    [string]$CasesPath = "",
    [string]$OutputDir = "target\owasp-benchmark-eval",
    [string]$SpaExe = "spa",
    [int]$Limit = 10,
    [int]$MaxTokens = 0,
    [ValidateSet("auto", "on", "off")]
    [string]$ReportOutput = "off",
    [switch]$RandomSample,
    [int]$Seed = 0,
    [switch]$SkipHealthCheck,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Join-BenchmarkUrl([string]$Base, [string]$PathOrUrl) {
    if ($PathOrUrl -match '^https?://') {
        return $PathOrUrl
    }
    $baseTrimmed = $Base.TrimEnd("/")
    $pathTrimmed = $PathOrUrl.TrimStart("/")
    return "$baseTrimmed/$pathTrimmed"
}

function Get-PropertyValue($Object, [string[]]$Names) {
    foreach ($name in $Names) {
        if ($Object.PSObject.Properties.Name -contains $name) {
            $value = $Object.$name
            if ($null -ne $value -and "$value".Trim().Length -gt 0) {
                return "$value"
            }
        }
    }
    return ""
}

function Get-BenchmarkTestId($Row) {
    $direct = Get-PropertyValue $Row @("# test name", "test name", "test_name", "testName", "id")
    if ($direct -match 'BenchmarkTest\d+') {
        return $Matches[0]
    }

    foreach ($property in $Row.PSObject.Properties) {
        if ("$($property.Value)" -match 'BenchmarkTest\d+') {
            return $Matches[0]
        }
    }

    return ""
}

function Convert-ExpectedRowToCase($Row) {
    $id = Get-BenchmarkTestId $Row
    if (-not $id) {
        return $null
    }

    $category = Get-PropertyValue $Row @("category", "Category", "Full Category Name")
    $vulnerable = Get-PropertyValue $Row @("real vulnerability", "real_vulnerability", "vulnerable")
    $cwe = Get-PropertyValue $Row @("cwe", "CWE")

    [pscustomobject]@{
        id = $id
        category = $category
        vulnerable = $vulnerable
        cwe = $cwe
        method = "GET"
        path = "/$id"
        params = @{}
        notes = "Generated from OWASP Benchmark expected results. Adjust method/params if the local benchmark version requires a specific request shape."
    }
}

function Read-BenchmarkCases {
    if ($CasesPath) {
        if (-not (Test-Path -LiteralPath $CasesPath)) {
            throw "CasesPath not found: $CasesPath"
        }
        $raw = Get-Content -LiteralPath $CasesPath -Raw
        $cases = $raw | ConvertFrom-Json
        return @($cases)
    }

    if ($ExpectedResultsCsv) {
        if (-not (Test-Path -LiteralPath $ExpectedResultsCsv)) {
            throw "ExpectedResultsCsv not found: $ExpectedResultsCsv"
        }
        $lines = Get-Content -LiteralPath $ExpectedResultsCsv
        if ($lines.Count -eq 0) {
            throw "ExpectedResultsCsv is empty: $ExpectedResultsCsv"
        }
        $lines[0] = $lines[0].TrimStart([char]0xFEFF)
        if ($lines[0].StartsWith("#")) {
            $lines[0] = $lines[0].TrimStart("#").TrimStart()
        }
        $rows = $lines | ConvertFrom-Csv
        $cases = @()
        foreach ($row in $rows) {
            $case = Convert-ExpectedRowToCase $row
            if ($null -ne $case) {
                $cases += $case
            }
            if ($Limit -gt 0 -and $cases.Count -ge $Limit) {
                break
            }
        }
        return $cases
    }

    throw "Provide -ExpectedResultsCsv from OWASP Benchmark or -CasesPath with a JSON case manifest."
}

function Convert-ValueToPromptText($Value) {
    if ($null -eq $Value) {
        return "none"
    }
    try {
        $json = $Value | ConvertTo-Json -Depth 12 -Compress
        if ($json -and $json -ne "{}") {
            return $json
        }
    } catch {
        return "$Value"
    }
    return "none"
}

function New-BenchmarkPrompt($Case, [string]$TargetUrl) {
    $method = Get-PropertyValue $Case @("method")
    if (-not $method) {
        $method = "GET"
    }

    $reportRequirement = if ($ReportOutput -eq "on") {
        @"
4. Produce a formal Markdown report in Chinese. Use the target host/path as the report name.
5. Use the SPA website-report structure configured by the runtime skill: probe object inventory, attack sample coverage, findings, and recommendations.
6. In attack coverage and findings, use the SPA four-level labels: 【高危】, 【危险】, 【警告】, or 【正常】.
7. Call generate_markdown_report after the report is complete and include the returned report path in the final answer.
"@
    } else {
        @"
4. Do not produce a Markdown file in this run. Return the evidence, verdict, and limitations directly in the final answer.
5. Keep the normal SPA vulnerability-discovery workflow: probe inventory, attack sample coverage, findings, and recommendations should still drive the reasoning.
"@
    }

    @"
You are evaluating this local, authorized web target with low-impact black-box vulnerability checks.

Target:
- Target URL: $TargetUrl
- Suggested method: $method

Requirements:
1. Test only this single target URL and same-origin paths discovered from it. Do not expand to unrelated targets.
2. Establish a baseline first, then use low-impact validation only. Do not destroy data or run load tests.
3. Use black-box HTTP/browser evidence only. Do not inspect local source files, expected-results files, prior score files, generated reports, benchmark metadata, or any local artifacts that reveal the intended weakness.
4. Do not use source/static semantic tools for this run, even if they are available.
5. If an input parameter is needed, actively try a bounded set of common black-box fields and locations such as visible fields, existing query parameters, route/path terms, common query names, headers, and cookies before asking for more data.
$reportRequirement
"@
}

New-Directory $OutputDir
$reportsDir = Join-Path $OutputDir "reports"
$promptsDir = Join-Path $OutputDir "prompts"
$logsDir = Join-Path $OutputDir "logs"
New-Directory $reportsDir
New-Directory $promptsDir
New-Directory $logsDir

if (-not $SkipHealthCheck) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($null -eq $curl) {
        throw "curl.exe not found. Re-run with -SkipHealthCheck or install curl."
    }
    $health = & curl.exe -k -s -L -o NUL -w "%{http_code}" $BaseUrl
    if ($LASTEXITCODE -ne 0 -or -not ($health -match '^(2|3|4)\d\d$')) {
        throw "Benchmark target is not reachable: $BaseUrl (curl status: $health). Start OWASP Benchmark first or pass the correct -BaseUrl."
    }
}

$cases = Read-BenchmarkCases
if ($RandomSample) {
    $random = if ($Seed -ne 0) {
        [System.Random]::new($Seed)
    } else {
        [System.Random]::new()
    }
    $cases = @($cases | Sort-Object { $random.Next() })
}
if ($Limit -gt 0) {
    $cases = @($cases | Select-Object -First $Limit)
}
if ($cases.Count -eq 0) {
    throw "No benchmark cases were loaded."
}

$previousReportDir = $env:SPA_AGENT_REPORT_DIR
if ($ReportOutput -eq "on") {
    $env:SPA_AGENT_REPORT_DIR = (Resolve-Path -LiteralPath $reportsDir).Path
}

$results = @()
try {
    $index = 0
    foreach ($case in $cases) {
        $index += 1
        $id = Get-PropertyValue $case @("id", "test_name", "# test name")
        if (-not $id) {
            $id = "case-$index"
        }

        $path = Get-PropertyValue $case @("url", "path")
        if (-not $path) {
            $path = "/$id"
        }
        $targetUrl = Join-BenchmarkUrl $BaseUrl $path
        $prompt = New-BenchmarkPrompt $case $targetUrl

        $safeId = ($id -replace '[^A-Za-z0-9_.-]', '_')
        $promptPath = Join-Path $promptsDir "$safeId.prompt.txt"
        $logPath = Join-Path $logsDir "$safeId.stdout.txt"
        Set-Content -LiteralPath $promptPath -Value $prompt -Encoding UTF8

        $startedAt = Get-Date
        if ($DryRun) {
            Write-Host "[$index/$($cases.Count)] Dry run $id -> $targetUrl"
            $output = @("Dry run: spa was not executed.", "Prompt: $promptPath")
            $exitCode = 0
        } else {
            Write-Host "[$index/$($cases.Count)] Running $id -> $targetUrl"
            $spaArgs = @("--mode", "eval", "--report", $ReportOutput, "--prompt", $prompt)
            if ($MaxTokens -gt 0) {
                $spaArgs += @("--max-tokens", "$MaxTokens")
            }
            $output = & $SpaExe @spaArgs 2>&1
            $exitCode = $LASTEXITCODE
        }
        $endedAt = Get-Date
        $output | Set-Content -LiteralPath $logPath -Encoding UTF8

        $results += [pscustomobject]@{
            id = $id
            category = Get-PropertyValue $case @("category", "Category")
            expected_vulnerable = Get-PropertyValue $case @("vulnerable", "real vulnerability", "real_vulnerability")
            cwe = Get-PropertyValue $case @("cwe", "CWE")
            target_url = $targetUrl
            prompt_path = $promptPath
            stdout_path = $logPath
            exit_code = $exitCode
            started_at = $startedAt.ToString("o")
            ended_at = $endedAt.ToString("o")
        }
    }
} finally {
    if ($null -eq $previousReportDir) {
        Remove-Item Env:\SPA_AGENT_REPORT_DIR -ErrorAction SilentlyContinue
    } else {
        $env:SPA_AGENT_REPORT_DIR = $previousReportDir
    }
}

$resultsPath = Join-Path $OutputDir "results.json"
$results | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $resultsPath -Encoding UTF8

Write-Host "OWASP Benchmark SPA eval complete."
Write-Host "Results: $resultsPath"
if ($ReportOutput -eq "on") {
    Write-Host "Reports: $reportsDir"
} else {
    Write-Host "Reports: disabled (pass -ReportOutput on to write Markdown reports)"
}
