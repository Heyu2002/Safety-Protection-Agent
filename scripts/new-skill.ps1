param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter(Mandatory = $true)]
    [string]$Description,

    [string]$DisplayName,

    [string]$ShortDescription,

    [string]$DefaultPrompt,

    [string]$Root,

    [switch]$NoResources
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = Join-Path $repoRoot "skills"
}

if ($Name -notmatch '^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$') {
    throw "Skill name must use lowercase letters, digits, and hyphens only, and be under 64 characters."
}

if ([string]::IsNullOrWhiteSpace($DisplayName)) {
    $nameParts = @(
        ($Name -split '-') | ForEach-Object {
        if ($_.Length -eq 0) {
            $_
        } else {
            $_.Substring(0, 1).ToUpperInvariant() + $_.Substring(1)
        }
    }
    )
    $DisplayName = $nameParts -join ' '
}

if ([string]::IsNullOrWhiteSpace($ShortDescription)) {
    $ShortDescription = $Description
}

if ([string]::IsNullOrWhiteSpace($DefaultPrompt)) {
    $DefaultPrompt = "Use `$$Name to help with this task."
}

function Escape-YamlString {
    param([string]$Value)
    return $Value.Replace('\', '\\').Replace('"', '\"')
}

function Apply-Template {
    param(
        [string]$Content,
        [hashtable]$Values
    )

    foreach ($key in $Values.Keys) {
        $Content = $Content.Replace("{{$key}}", $Values[$key])
    }

    return $Content
}

function Write-Utf8NoBom {
    param(
        [string]$Path,
        [string]$Content
    )

    $encoding = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

$skillDir = Join-Path $Root $Name
if (Test-Path -LiteralPath $skillDir) {
    throw "Skill already exists: $skillDir"
}

$skillTemplate = @'
---
name: {{name}}
description: {{description}}
---

# {{display_name}}

## Quick Start

- Identify whether this skill applies to the user's request.
- Load only the references needed for the current task.
- Use scripts for deterministic operations instead of rewriting repetitive code.

## Workflow

1. Confirm the task goal and required inputs.
2. Read relevant files from `references/` only when needed.
3. Run or adapt scripts from `scripts/` when deterministic behavior is important.
4. Use files from `assets/` as templates or output resources.
5. Validate the result before responding.

## Resources

- `references/`: detailed guidance and domain references.
- `scripts/`: executable helpers.
- `assets/`: templates, sample files, or reusable output assets.
'@

$openAiTemplate = @'
interface:
  display_name: "{{display_name}}"
  short_description: "{{short_description}}"
  default_prompt: "{{default_prompt}}"
'@

$values = @{
    name = $Name
    description = $Description
    display_name = $DisplayName
    short_description = $ShortDescription
    default_prompt = $DefaultPrompt
}

$yamlValues = @{
    display_name = Escape-YamlString $DisplayName
    short_description = Escape-YamlString $ShortDescription
    default_prompt = Escape-YamlString $DefaultPrompt
}

New-Item -ItemType Directory -Force -Path $skillDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $skillDir "agents") | Out-Null

if (-not $NoResources) {
    foreach ($resourceDir in @("scripts", "references", "assets")) {
        $path = Join-Path $skillDir $resourceDir
        New-Item -ItemType Directory -Force -Path $path | Out-Null
        New-Item -ItemType File -Force -Path (Join-Path $path ".gitkeep") | Out-Null
    }
}

Write-Utf8NoBom (Join-Path $skillDir "SKILL.md") (Apply-Template $skillTemplate $values)
Write-Utf8NoBom (Join-Path $skillDir "agents\openai.yaml") (Apply-Template $openAiTemplate $yamlValues)

Write-Host "Created skill scaffold: $skillDir"
