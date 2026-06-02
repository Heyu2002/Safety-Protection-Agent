param(
    [string]$BaseUrl = "https://localhost:8443/benchmark",
    [string]$ExpectedResultsCsv = "",
    [string]$CasesPath = "",
    [string]$OutputDir = "target\owasp-benchmark-score",
    [string]$SpaExe = "",
    [ValidateSet("spa", "codex")]
    [string]$Runner = "spa",
    [string]$CodexCommand = "",
    [string]$CodexWorkDir = "",
    [string]$CodexModel = "",
    [string[]]$CodexExtraArgs = @(),
    [string[]]$CaseIds = @(),
    [int]$Limit = 10,
    [int]$MaxTokens = 0,
    [ValidateSet("auto", "on", "off")]
    [string]$ReportOutput = "off",
    [int]$Jobs = 1,
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

function Convert-ExpectedValueToBool([string]$Value) {
    $normalized = $Value.Trim().ToLowerInvariant()
    if ($normalized -in @("true", "1", "yes", "y")) {
        return $true
    }
    if ($normalized -in @("false", "0", "no", "n")) {
        return $false
    }
    throw "Unsupported expected vulnerable value: $Value"
}

function Convert-ExpectedRowToCase($Row) {
    $id = Get-BenchmarkTestId $Row
    if (-not $id) {
        return $null
    }

    [pscustomobject]@{
        id = $id
        category = Get-PropertyValue $Row @("category", "Category", "Full Category Name")
        expected_vulnerable = Get-PropertyValue $Row @("real vulnerability", "real_vulnerability", "vulnerable")
        cwe = Get-PropertyValue $Row @("cwe", "CWE")
        method = "GET"
        path = "/$id"
        params = @{}
    }
}

function Read-BenchmarkCases {
    if ($CasesPath) {
        if (-not (Test-Path -LiteralPath $CasesPath)) {
            throw "CasesPath not found: $CasesPath"
        }
        $raw = Get-Content -LiteralPath $CasesPath -Raw
        return @($raw | ConvertFrom-Json)
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
        }
        return $cases
    }

    throw "Provide -ExpectedResultsCsv from OWASP Benchmark or -CasesPath with a JSON case manifest."
}

function Resolve-SpaExe([string]$Requested) {
    if ($Requested) {
        return $Requested
    }
    $localSpa = Join-Path (Get-Location).Path "target\debug\spa.exe"
    if (Test-Path -LiteralPath $localSpa) {
        return $localSpa
    }
    return "spa"
}

function Resolve-CodexCommand([string]$Requested) {
    if ($Requested) {
        return $Requested
    }
    $cmdShim = Get-Command "codex.cmd" -ErrorAction SilentlyContinue
    if ($null -ne $cmdShim) {
        return $cmdShim.Source
    }
    $cmd = Get-Command "codex" -ErrorAction SilentlyContinue
    if ($null -ne $cmd) {
        return $cmd.Source
    }
    return "codex"
}

function New-ScorePrompt($Case, [string]$TargetUrl) {
    $id = Get-PropertyValue $Case @("id", "test_name", "# test name")
    $category = Get-PropertyValue $Case @("category", "Category")
    $cwe = Get-PropertyValue $Case @("cwe", "CWE")
    $method = Get-PropertyValue $Case @("method")
    if (-not $method) {
        $method = "GET"
    }

    $promptLines = @(
        "You are evaluating one local, authorized OWASP Benchmark case.",
        "",
        "Task:",
        "Decide whether this exact target is vulnerable for the focused weakness. This is a blind scoring run. Use the same active probing workflow as normal SPA web vulnerability discovery; only the final output contract is score-oriented.",
        "",
        "Target:",
        "- Case ID: $id",
        "- Target URL: $TargetUrl",
        "- Suggested method: $method",
        "- Focus category: $category",
        "- Focus CWE: $cwe",
        "",
        "Rules:",
        "1. Test only this single case. Do not expand to unrelated targets.",
        "2. Use low-impact checks only. Do not destroy data, exfiltrate secrets, run load tests, or persist changes.",
        "3. If the page exposes no parameter, try only a small set of reasonable parameters and locations for this weakness, including vector, case ID, common query fields, headers, and cookies.",
        "4. Judge from runtime HTTP/browser evidence first. Hash/crypto/weakrand cases may use an available source/static semantic tool for this single case to identify the algorithm, cipher mode, or randomness API. SQLi/LDAPI/XPathi/trustbound cases may use an available source/static semantic tool for this single case when runtime responses are collapsed or do not expose a usable delta. Do not inspect expected-results files or prior score files, and do not call the spa binary to answer this case.",
        "5. The target is local authorized HTTPS and may use a self-signed certificate. If a client blocks local certificate validation, use a localhost-only certificate bypass and continue.",
        "6. Do not assume the target is vulnerable just because this is OWASP Benchmark.",
        "6a. For hash/crypto cases, generic runtime banners such as MessageDigest.getInstance or Cipher.getInstance executed are not enough. Use weak algorithm/mode evidence such as MD5, SHA-1, DES, RC4, ECB, or provider-default AES; if the algorithm cannot be identified, return inconclusive.",
        "6b. For weakrand cases, generic runtime banners such as Weak Randomness Test executed are not enough. Use java_randomness_semantic_scan when available; java.util.Random, Math.random, or ThreadLocalRandom support vulnerable, while SecureRandom supports not_vulnerable unless predictable seeding is shown.",
        "6c. For SQLi/LDAPI/XPathi/trustbound cases, if black-box probes hit a fixed generic response or no useful delta, use java_injection_semantic_scan with this case_id when available. Tainted request data reaching SQL/LDAP/XPath/session sinks supports vulnerable; constants or benchmark safe helpers reaching the sink support not_vulnerable.",
        "6d. For trustbound cases, a reachable session write alone is not enough. Require user-controlled session key/value influence or source-level taint into setAttribute/putValue before returning vulnerable.",
        "7. End your final answer with exactly one single-line JSON object and no Markdown after it.",
        "8. The JSON object must contain these fields: case_id, verdict, confidence, evidence, tested_inputs.",
        "9. verdict must be one of: vulnerable, not_vulnerable, inconclusive.",
        "",
        "Verdict guidance:",
        "- vulnerable: runtime evidence confirms the focused weakness, or a dangerous sink/security boundary is reachable with weakness-specific observable behavior in this authorized benchmark case.",
        "- not_vulnerable: a valid baseline and representative focused low-impact checks across likely inputs found stable negative evidence.",
        "- inconclusive: the target is unreachable, the correct input shape is unknown after bounded discovery, the baseline is unusable, or evidence is insufficient."
    )
    return ($promptLines -join [Environment]::NewLine)
}

function Invoke-SpaCase {
    param(
        [string]$SpaCommand,
        [string]$Prompt,
        [ValidateSet("auto", "on", "off")]
        [string]$ReportOutput,
        [int]$MaxTokens
    )

    $spaArgs = @("--mode", "eval", "--report", $ReportOutput, "--prompt", $Prompt)
    if ($MaxTokens -gt 0) {
        $spaArgs += @("--max-tokens", "$MaxTokens")
    }

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $SpaCommand @spaArgs 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    [pscustomobject]@{
        output = @($output)
        exit_code = $exitCode
    }
}

function Invoke-CodexCase {
    param(
        [string]$CodexCommand,
        [string]$WorkDir,
        [string]$Prompt,
        [string]$LastMessagePath,
        [string]$Model,
        [string[]]$ExtraArgs
    )

    New-Directory $WorkDir
    $codexArgs = @(
        "exec",
        "-C", $WorkDir,
        "-s", "danger-full-access",
        "--dangerously-bypass-approvals-and-sandbox",
        "--color", "never",
        "--ephemeral",
        "--ignore-rules",
        "--skip-git-repo-check",
        "-o", $LastMessagePath
    )
    if ($Model) {
        $codexArgs += @("-m", $Model)
    }
    if ($ExtraArgs -and $ExtraArgs.Count -gt 0) {
        $codexArgs += $ExtraArgs
    }
    $codexArgs += "-"

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = $Prompt | & $CodexCommand @codexArgs 2>&1
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if (Test-Path -LiteralPath $LastMessagePath) {
        $lastMessage = Get-Content -LiteralPath $LastMessagePath -Raw
        if ($lastMessage.Trim().Length -gt 0) {
            $output = @($output) + @("", "--- codex last message ---", $lastMessage)
        }
    }

    [pscustomobject]@{
        output = @($output)
        exit_code = $exitCode
    }
}

function Get-LastVerdictJson([string]$Text) {
    $verdictNeedle = ([char]34) + "verdict" + ([char]34)
    $Text = [regex]::Replace($Text, "`e\[[0-9;?]*[ -/]*[@-~]", "")
    $lines = $Text -split "`r?`n"
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
        $line = $lines[$i].Trim()
        if ($line.StartsWith("agent>")) {
            $line = $line.Substring(6).Trim()
        }
        if ($line.StartsWith('```')) {
            continue
        }
        if ($line.Contains($verdictNeedle) -and $line.StartsWith("{") -and $line.EndsWith("}")) {
            try {
                return $line | ConvertFrom-Json
            } catch {
            }
        }
    }

    $candidates = @(Get-BalancedJsonCandidates $Text)
    for ($i = $candidates.Count - 1; $i -ge 0; $i--) {
        if (-not $candidates[$i].Contains($verdictNeedle)) {
            continue
        }
        try {
            return $candidates[$i] | ConvertFrom-Json
        } catch {
        }
    }

    $verdictMatch = [regex]::Match($Text, '"verdict"\s*:\s*"(?<verdict>[^"\\]*(?:\\.[^"\\]*)*)"')
    if ($verdictMatch.Success) {
        $caseIdMatch = [regex]::Match($Text, '"case_id"\s*:\s*"(?<case_id>BenchmarkTest\d+)"')
        $confidenceMatch = [regex]::Match($Text, '"confidence"\s*:\s*"?(?<confidence>[A-Za-z0-9_.-]+)"?')
        return [pscustomobject]@{
            case_id = if ($caseIdMatch.Success) { $caseIdMatch.Groups["case_id"].Value } else { "" }
            verdict = $verdictMatch.Groups["verdict"].Value
            confidence = if ($confidenceMatch.Success) { $confidenceMatch.Groups["confidence"].Value } else { $null }
            evidence = @("verdict-only fallback parse; final JSON was malformed")
            tested_inputs = @()
        }
    }

    return $null
}

function Get-BalancedJsonCandidates([string]$Text) {
    $candidates = New-Object System.Collections.Generic.List[string]
    $depth = 0
    $start = -1
    $inString = $false
    $escaped = $false

    for ($i = 0; $i -lt $Text.Length; $i++) {
        $ch = $Text[$i]
        if ($inString) {
            if ($escaped) {
                $escaped = $false
            } elseif ($ch -eq '\') {
                $escaped = $true
            } elseif ($ch -eq '"') {
                $inString = $false
            }
            continue
        }

        if ($ch -eq '"') {
            $inString = $true
            continue
        }
        if ($ch -eq '{') {
            if ($depth -eq 0) {
                $start = $i
            }
            $depth += 1
            continue
        }
        if ($ch -eq '}' -and $depth -gt 0) {
            $depth -= 1
            if ($depth -eq 0 -and $start -ge 0) {
                $candidates.Add($Text.Substring($start, $i - $start + 1))
                $start = -1
            }
        }
    }

    return $candidates
}

function Convert-VerdictToBool($Verdict) {
    if ($null -eq $Verdict) {
        return $null
    }
    $normalized = "$Verdict".Trim().ToLowerInvariant()
    if ($normalized -in @("vulnerable", "true", "yes")) {
        return $true
    }
    if ($normalized -in @("not_vulnerable", "not-vulnerable", "safe", "false", "no")) {
        return $false
    }
    return $null
}

function New-CoverageInfo([string]$Status, [string]$Tools, [string]$Next) {
    [pscustomobject]@{
        status = $Status
        tools = $Tools
        next = $Next
    }
}

function Get-ToolCoverageInfo([string]$Category) {
    $normalized = $Category.ToLowerInvariant()
    if ($normalized -eq "sqli") {
        return [pscustomobject]@{ status = "covered-specific+static"; tools = "database_risk_scan, java_injection_semantic_scan"; next = "Expand SQL semantic rules for prepared bindings, sanitizers, and multi-method helper flows." }
    }
    if ($normalized -eq "xss") {
        return [pscustomobject]@{ status = "covered-specific"; tools = "xss_risk_scan"; next = "Use MCP browser evidence for DOM/execution confirmation when needed." }
    }
    if ($normalized -eq "securecookie") {
        return [pscustomobject]@{ status = "covered-specific"; tools = "http_security_headers_scan, weak_session_id_scan"; next = "Confirm cookie flags and the real token generation endpoint." }
    }
    if ($normalized -eq "pathtraver") {
        return [pscustomobject]@{ status = "covered-generic"; tools = "http_active_probe_scan"; next = "Tune file-name, header, cookie, and source-location discovery from FN samples." }
    }
    if ($normalized -eq "cmdi") {
        return [pscustomobject]@{ status = "covered-generic"; tools = "http_active_probe_scan"; next = "Expand low-impact echo markers and header/cookie/source discovery." }
    }
    if ($normalized -eq "ldapi") {
        return [pscustomobject]@{ status = "covered-generic+static"; tools = "http_active_probe_scan, java_injection_semantic_scan"; next = "Expand LDAP semantic rules for escaping helpers and multi-method dataflow." }
    }
    if ($normalized -eq "trustbound") {
        return [pscustomobject]@{ status = "covered-generic+static"; tools = "http_active_probe_scan, java_injection_semantic_scan"; next = "Add second-read runtime verification for session/state-key influence." }
    }
    if ($normalized -eq "xpathi") {
        return [pscustomobject]@{ status = "covered-generic+static"; tools = "http_active_probe_scan, java_injection_semantic_scan"; next = "Expand XPath semantic rules for collections, sanitizers, and multi-method dataflow." }
    }
    if ($normalized -eq "crypto") {
        return [pscustomobject]@{ status = "covered-static"; tools = "java_crypto_semantic_scan"; next = "Keep expanding crypto semantic rules for key/IV generation and authenticated encryption." }
    }
    if ($normalized -eq "hash") {
        return [pscustomobject]@{ status = "covered-static"; tools = "java_crypto_semantic_scan"; next = "Keep expanding hash semantic rules for password-hashing context and custom wrappers." }
    }
    if ($normalized -eq "weakrand") {
        return [pscustomobject]@{ status = "covered-static+partial-runtime"; tools = "java_randomness_semantic_scan, weak_session_id_scan partial"; next = "Add generic runtime randomness sampling for reflected/body/header tokens and predictable seeding patterns." }
    }
    return [pscustomobject]@{ status = "unknown"; tools = "none"; next = "Inspect this category and map it to an existing tool or add a new one." }
}

function New-ToolCoveragePlan {
    param(
        [object[]]$Cases,
        [object[]]$Results
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("# OWASP Benchmark Tool Coverage Plan")
    $lines.Add("")
    $lines.Add("This plan is generated from the evaluated case set. It identifies whether the current SPA toolset can handle each sampled vulnerability category and what tool work remains.")
    $lines.Add("")
    $lines.Add("| Category | Cases | Outcomes | Coverage | Current tools | Direct next work |")
    $lines.Add("| --- | ---: | --- | --- | --- | --- |")

    $categories = @($Cases | ForEach-Object { Get-PropertyValue $_ @("category", "Category") } | Where-Object { $_ } | Sort-Object -Unique)
    foreach ($category in $categories) {
        $caseCount = @($Cases | Where-Object { (Get-PropertyValue $_ @("category", "Category")) -eq $category }).Count
        $categoryResults = @($Results | Where-Object { $_.category -eq $category })
        $outcomes = if ($categoryResults.Count -gt 0) {
            @($categoryResults | Group-Object outcome | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ", "
        } else {
            "not-run"
        }
        $info = Get-ToolCoverageInfo $category
        $lines.Add("| $category | $caseCount | $outcomes | $($info.status) | $($info.tools) | $($info.next) |")
    }

    $lines.Add("")
    $lines.Add("Execution order:")
    $lines.Add("1. Use `http_active_probe_scan` for sampled path traversal, command injection, LDAP injection, and trust-boundary cases before asking for missing parameters.")
    $lines.Add("2. Use `java_crypto_semantic_scan` for crypto/hash cases, `java_randomness_semantic_scan` for weakrand cases, and `java_injection_semantic_scan` for SQLi/LDAPI/XPathi/trustbound cases where runtime responses are collapsed or source-to-sink proof is needed.")
    $lines.Add("3. Add runtime randomness sampling for reflected/body/header tokens before treating weakrand outside Java benchmark sources as fully covered.")
    $lines.Add("4. Add XPath-specific active payloads/signals if source is unavailable for `xpathi`.")
    $lines.Add("5. Re-run this scoring script and compare TP/FP/FN by category.")

    return ($lines -join [Environment]::NewLine)
}

function New-ScoreSummary([string]$RunnerName, [object[]]$Results) {
    $total = $Results.Count
    $tp = @($Results | Where-Object { $_.outcome -eq "TP" }).Count
    $fp = @($Results | Where-Object { $_.outcome -eq "FP" }).Count
    $tn = @($Results | Where-Object { $_.outcome -eq "TN" }).Count
    $fn = @($Results | Where-Object { $_.outcome -eq "FN" }).Count
    $inconclusive = @($Results | Where-Object { $_.outcome -eq "inconclusive" }).Count
    $parseErrors = @($Results | Where-Object { $_.outcome -eq "parse_error" }).Count
    $executionErrors = @($Results | Where-Object { $_.outcome -eq "execution_error" }).Count
    $decided = $tp + $fp + $tn + $fn
    $correct = $tp + $tn

    $strictAccuracy = 0
    if ($total -gt 0) {
        $strictAccuracy = [math]::Round($correct / $total, 4)
    }
    $decidedAccuracy = $null
    if ($decided -gt 0) {
        $decidedAccuracy = [math]::Round($correct / $decided, 4)
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
        strict_accuracy = $strictAccuracy
        decided_accuracy = $decidedAccuracy
        precision = $precision
        recall = $recall
        f1 = $f1
    }
}

function Write-ScoreArtifacts {
    param(
        [string]$RunnerName,
        [string]$BaseUrlValue,
        [string]$ExpectedResultsCsvValue,
        [string]$CasesPathValue,
        [object[]]$Cases,
        [object[]]$Results,
        [string]$OutputDirValue
    )

    $summary = New-ScoreSummary $RunnerName $Results
    $score = [pscustomobject]@{
        runner = $RunnerName
        base_url = $BaseUrlValue
        expected_results_csv = $ExpectedResultsCsvValue
        cases_path = $CasesPathValue
        summary = $summary
        results = $Results
    }

    $scorePath = Join-Path $OutputDirValue "score.json"
    $csvPath = Join-Path $OutputDirValue "score.csv"
    $coveragePlanPath = Join-Path $OutputDirValue "tool-coverage-plan.md"
    $score | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $scorePath -Encoding UTF8
    $Results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    New-ToolCoveragePlan $Cases $Results | Set-Content -LiteralPath $coveragePlanPath -Encoding UTF8

    return $summary
}

function Read-PartialResults {
    param(
        [string[]]$ResultDirs,
        [object[]]$Cases
    )

    $byId = @{}
    foreach ($dir in $ResultDirs) {
        $partialDir = Join-Path $dir "partial-results"
        if (-not (Test-Path -LiteralPath $partialDir)) {
            continue
        }
        foreach ($file in Get-ChildItem -LiteralPath $partialDir -Filter "*.result.json") {
            try {
                $result = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
                if ($result.id) {
                    $byId["$($result.id)"] = $result
                }
            } catch {
                Write-Warning "Ignoring unreadable partial result $($file.FullName): $_"
            }
        }
    }

    $ordered = @()
    foreach ($case in $Cases) {
        $id = Get-PropertyValue $case @("id", "test_name", "# test name")
        if ($byId.ContainsKey($id)) {
            $ordered += $byId[$id]
        }
    }
    return @($ordered)
}

function Invoke-ParallelScoreRun {
    param(
        [object[]]$Cases,
        [int]$JobCount,
        [string]$OutputDirValue,
        [string]$RunnerName,
        [string]$BaseUrlValue,
        [string]$ExpectedResultsCsvValue,
        [string]$ReportOutputValue,
        [string]$SpaCommand,
        [string]$CodexCommandValue,
        [string]$CodexModelValue,
        [string[]]$CodexExtraArgsValue,
        [int]$MaxTokensValue,
        [switch]$DryRunValue
    )

    if (-not $PSCommandPath) {
        throw "-Jobs requires running this script from a file path."
    }

    $effectiveJobs = [math]::Min($JobCount, $Cases.Count)
    $workersDir = Join-Path $OutputDirValue "workers"
    New-Directory $workersDir

    $processes = @()
    $workerOutputDirs = @()
    for ($worker = 0; $worker -lt $effectiveJobs; $worker++) {
        $workerCases = @()
        for ($index = $worker; $index -lt $Cases.Count; $index += $effectiveJobs) {
            $workerCases += $Cases[$index]
        }
        if ($workerCases.Count -eq 0) {
            continue
        }

        $workerName = "worker-$($worker + 1)"
        $workerDir = Join-Path $workersDir $workerName
        $workerCasesPath = Join-Path $workersDir "$workerName.cases.json"
        $stdoutPath = Join-Path $workersDir "$workerName.stdout.log"
        $stderrPath = Join-Path $workersDir "$workerName.stderr.log"
        New-Directory $workerDir
        $workerCases | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $workerCasesPath -Encoding UTF8
        $workerOutputDirs += $workerDir

        $args = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", $PSCommandPath,
            "-BaseUrl", $BaseUrlValue,
            "-CasesPath", $workerCasesPath,
            "-OutputDir", $workerDir,
            "-Runner", $RunnerName,
            "-Limit", "0",
            "-ReportOutput", $ReportOutputValue,
            "-Jobs", "1",
            "-SkipHealthCheck"
        )
        if ($SpaCommand) {
            $args += @("-SpaExe", $SpaCommand)
        }
        if ($CodexCommandValue) {
            $args += @("-CodexCommand", $CodexCommandValue)
        }
        if ($CodexModelValue) {
            $args += @("-CodexModel", $CodexModelValue)
        }
        if ($CodexExtraArgsValue -and $CodexExtraArgsValue.Count -gt 0) {
            $args += @("-CodexExtraArgs")
            $args += $CodexExtraArgsValue
        }
        if ($MaxTokensValue -gt 0) {
            $args += @("-MaxTokens", "$MaxTokensValue")
        }
        if ($DryRunValue) {
            $args += "-DryRun"
        }
        if ($RunnerName -eq "codex") {
            $args += @("-CodexWorkDir", (Join-Path $workerDir "codex-workdir"))
        }

        $process = Start-Process -FilePath "powershell.exe" `
            -ArgumentList $args `
            -WorkingDirectory (Get-Location).Path `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -WindowStyle Hidden `
            -PassThru

        $processes += [pscustomobject]@{
            name = $workerName
            process = $process
            output_dir = $workerDir
            stdout = $stdoutPath
            stderr = $stderrPath
            cases = $workerCases.Count
        }
    }

    Write-Host "Started $($processes.Count) $RunnerName worker(s) for $($Cases.Count) case(s)."
    do {
        $running = @()
        foreach ($entry in $processes) {
            $entry.process.Refresh()
            if (-not $entry.process.HasExited) {
                $running += $entry
            }
        }
        $results = @(Read-PartialResults $workerOutputDirs $Cases)
        Write-Host "Parallel progress: $(@($results).Count)/$($Cases.Count) case(s) complete; running workers: $($running.Count)."
        if ($running.Count -gt 0) {
            Start-Sleep -Seconds 30
        }
    } while ($running.Count -gt 0)

    foreach ($entry in $processes) {
        $entry.process.WaitForExit()
        $entry.process.Refresh()
        if ($null -ne $entry.process.ExitCode -and $entry.process.ExitCode -ne 0) {
            Write-Warning "$($entry.name) exited with code $($entry.process.ExitCode). See $($entry.stdout) and $($entry.stderr)."
        }
    }

    $results = @(Read-PartialResults $workerOutputDirs $Cases)
    $summary = Write-ScoreArtifacts `
        -RunnerName $RunnerName `
        -BaseUrlValue $BaseUrlValue `
        -ExpectedResultsCsvValue $ExpectedResultsCsvValue `
        -CasesPathValue "" `
        -Cases $Cases `
        -Results $results `
        -OutputDirValue $OutputDirValue

    if (@($results).Count -lt $Cases.Count) {
        Write-Warning "Only $(@($results).Count)/$($Cases.Count) case(s) completed. Partial worker results were preserved under $workersDir."
    }

    Write-Host "OWASP Benchmark $RunnerName parallel scoring complete."
    Write-Host "Score: $(Join-Path $OutputDirValue 'score.json')"
    Write-Host "CSV: $(Join-Path $OutputDirValue 'score.csv')"
    Write-Host "Tool coverage plan: $(Join-Path $OutputDirValue 'tool-coverage-plan.md')"
    $summary | Format-List
}

New-Directory $OutputDir
$promptsDir = Join-Path $OutputDir "prompts"
$logsDir = Join-Path $OutputDir "logs"
$partialDir = Join-Path $OutputDir "partial-results"
New-Directory $promptsDir
New-Directory $logsDir
New-Directory $partialDir

if (-not $SkipHealthCheck) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($null -eq $curl) {
        throw "curl.exe not found. Re-run with -SkipHealthCheck or install curl."
    }
    $health = & curl.exe --ssl-no-revoke -k -s -L -o NUL -w "%{http_code}" $BaseUrl
    if ($LASTEXITCODE -ne 0 -or -not ($health -match '^(2|3|4)\d\d$')) {
        throw "Benchmark target is not reachable: $BaseUrl (curl status: $health)."
    }
}

$spaCommand = Resolve-SpaExe $SpaExe
$codexCommandResolved = Resolve-CodexCommand $CodexCommand
$codexEvalRoot = if ($CodexWorkDir) {
    $CodexWorkDir
} else {
    Join-Path $OutputDir "codex-workdir"
}
$cases = Read-BenchmarkCases
if ($CaseIds -and $CaseIds.Count -gt 0) {
    $wantedCaseIds = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]($CaseIds | ForEach-Object { "$_".Split(",") } | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    )
    $cases = @($cases | Where-Object {
        $caseId = Get-PropertyValue $_ @("id", "test_name", "# test name")
        $wantedCaseIds.Contains($caseId)
    })
}
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
if ($Jobs -lt 1) {
    throw "Jobs must be greater than zero."
}
if ($Jobs -gt 1 -and $cases.Count -gt 1) {
    Invoke-ParallelScoreRun `
        -Cases $cases `
        -JobCount $Jobs `
        -OutputDirValue $OutputDir `
        -RunnerName $Runner `
        -BaseUrlValue $BaseUrl `
        -ExpectedResultsCsvValue $ExpectedResultsCsv `
        -ReportOutputValue $ReportOutput `
        -SpaCommand $spaCommand `
        -CodexCommandValue $codexCommandResolved `
        -CodexModelValue $CodexModel `
        -CodexExtraArgsValue $CodexExtraArgs `
        -MaxTokensValue $MaxTokens `
        -DryRunValue:$DryRun
    exit
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
        $prompt = New-ScorePrompt $case $targetUrl

        $safeId = ($id -replace '[^A-Za-z0-9_.-]', '_')
        $promptPath = Join-Path $promptsDir "$safeId.prompt.txt"
        $logPath = Join-Path $logsDir "$safeId.stdout.txt"
        $lastMessagePath = Join-Path $logsDir "$safeId.codex-last-message.txt"
        $partialPath = Join-Path $partialDir "$safeId.result.json"
        Set-Content -LiteralPath $promptPath -Value $prompt -Encoding UTF8

        if (Test-Path -LiteralPath $partialPath) {
            Write-Host "[$index/$($cases.Count)] Reusing partial $Runner $id"
            $results += Get-Content -LiteralPath $partialPath -Raw | ConvertFrom-Json
            continue
        }

        $expected = Convert-ExpectedValueToBool (Get-PropertyValue $case @("expected_vulnerable", "vulnerable", "real vulnerability", "real_vulnerability"))
        $startedAt = Get-Date
        if ($DryRun) {
            Write-Host "[$index/$($cases.Count)] Dry run $Runner $id -> $targetUrl"
            $dryRunVerdict = [pscustomobject]@{
                case_id = $id
                verdict = "inconclusive"
                confidence = 0.0
                evidence = @("dry run")
                tested_inputs = @()
            }
            $output = @($dryRunVerdict | ConvertTo-Json -Compress)
            $exitCode = 0
        } else {
            Write-Host "[$index/$($cases.Count)] Scoring $Runner $id -> $targetUrl"
            if ($Runner -eq "spa") {
                $runResult = Invoke-SpaCase `
                    -SpaCommand $spaCommand `
                    -Prompt $prompt `
                    -ReportOutput $ReportOutput `
                    -MaxTokens $MaxTokens
            } elseif ($Runner -eq "codex") {
                $caseWorkDir = Join-Path $codexEvalRoot $safeId
                $runResult = Invoke-CodexCase `
                    -CodexCommand $codexCommandResolved `
                    -WorkDir $caseWorkDir `
                    -Prompt $prompt `
                    -LastMessagePath $lastMessagePath `
                    -Model $CodexModel `
                    -ExtraArgs $CodexExtraArgs
            } else {
                throw "Unsupported runner: $Runner"
            }
            $output = @($runResult.output)
            $exitCode = $runResult.exit_code
        }
        $endedAt = Get-Date
        $output | Set-Content -LiteralPath $logPath -Encoding UTF8

        $text = $output -join "`n"
        $verdictJson = Get-LastVerdictJson $text
        $verdict = "parse_error"
        $confidence = $null
        $predicted = $null
        if ($null -ne $verdictJson) {
            $verdict = "$($verdictJson.verdict)"
            if ($verdictJson.PSObject.Properties.Name -contains "confidence") {
                $confidence = $verdictJson.confidence
            }
            $predicted = Convert-VerdictToBool $verdict
        }
        if ($exitCode -ne 0) {
            $verdict = "execution_error"
            $predicted = $null
        }

        $outcome = "inconclusive"
        if ($null -ne $predicted) {
            if ($expected -and $predicted) {
                $outcome = "TP"
            } elseif ((-not $expected) -and $predicted) {
                $outcome = "FP"
            } elseif ((-not $expected) -and (-not $predicted)) {
                $outcome = "TN"
            } elseif ($expected -and (-not $predicted)) {
                $outcome = "FN"
            }
        } elseif ($verdict -eq "parse_error") {
            $outcome = "parse_error"
        } elseif ($verdict -eq "execution_error") {
            $outcome = "execution_error"
        }

        $result = [pscustomobject]@{
            id = $id
            category = Get-PropertyValue $case @("category", "Category")
            cwe = Get-PropertyValue $case @("cwe", "CWE")
            expected_vulnerable = $expected
            verdict = $verdict
            predicted_vulnerable = $predicted
            confidence = $confidence
            outcome = $outcome
            target_url = $targetUrl
            runner = $Runner
            prompt_path = $promptPath
            stdout_path = $logPath
            codex_last_message_path = if ($Runner -eq "codex") { $lastMessagePath } else { $null }
            exit_code = $exitCode
            seconds = [math]::Round(($endedAt - $startedAt).TotalSeconds, 1)
            started_at = $startedAt.ToString("o")
            ended_at = $endedAt.ToString("o")
        }
        $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $partialPath -Encoding UTF8
        $results += $result
    }
} finally {
}

$summary = Write-ScoreArtifacts `
    -RunnerName $Runner `
    -BaseUrlValue $BaseUrl `
    -ExpectedResultsCsvValue $ExpectedResultsCsv `
    -CasesPathValue $CasesPath `
    -Cases $cases `
    -Results $results `
    -OutputDirValue $OutputDir

Write-Host "OWASP Benchmark $Runner scoring complete."
Write-Host "Score: $(Join-Path $OutputDir 'score.json')"
Write-Host "CSV: $(Join-Path $OutputDir 'score.csv')"
Write-Host "Tool coverage plan: $(Join-Path $OutputDir 'tool-coverage-plan.md')"
if ($Runner -eq "spa") {
    Write-Host "SPA command: $spaCommand"
} elseif ($Runner -eq "codex") {
    Write-Host "Codex command: $codexCommandResolved"
    Write-Host "Codex workdir root: $codexEvalRoot"
}
$summary | Format-List
