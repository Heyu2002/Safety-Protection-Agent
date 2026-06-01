# Safety Protection Agent

[中文文档](README_CN.md)

`spa` is a Rust security agent for authorized defensive testing. It provides a
Codex-style terminal loop, model tool calling, MCP integration, runtime skills,
and focused security tools for local labs and owned systems.

It is built for authorized validation only. Do not use it for unauthorized
access, stealth, persistence, or data theft.

## Install

```powershell
Copy-Item .env.example .env
cargo run --bin spa
```

Optional local install on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
spa
```

Useful REPL commands:

```text
/help
/compact
/clear
/mcp
/exit
```

## Configure

Set the model provider in `.env`. The supported providers and common relay
examples are documented in `.env.example`.

Common paths:

```env
LLM_PROVIDER=codex-chatgpt
```

```env
LLM_PROVIDER=openai-responses
LLM_API_KEY=your-key
LLM_MODEL=your-model
LLM_BASE_URL=https://provider.example.com/v1
```

If a Chat Completions-compatible relay rejects native tool parameters, use:

```env
LLM_NATIVE_TOOLS=false
```

To let completed reports be written by the report tool:

```env
SPA_AGENT_REPORT_DIR=reports
```

Reports are written only when the model calls `generate_markdown_report`.

## MCP

Register MCP servers with the CLI:

```powershell
spa mcp add chrome-devtools -- npx chrome-devtools-mcp@latest --isolated --no-usage-statistics
spa mcp list
```

Configured MCP tools are exposed to the model at agent-turn start. The model
decides whether to call them.

SPA can also run as an MCP server:

```powershell
cargo run --bin spa-mcp
```

The agent red-team lab MCP server is separate:

```powershell
cargo run --bin spa-agent-lab-mcp
```

## Skills

Runtime skills live in `skills/`. The host exposes the skill catalog to the
model, the model selects relevant skills, and the selected `SKILL.md` bodies are
added to the agent context.

Included skills:

- `web-vulnerability-discovery`
- `isolated-web-security-assessment`
- `agent-redteam-lab`

Create a new skill:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-skill.ps1 -Name skill-name -Description "Use when ..."
```

## Tools

Built-in tools cover low-impact security checks and reporting:

- `http_security_headers_scan`
- `database_risk_scan`
- `xss_risk_scan`
- `weak_session_id_scan`
- `http_load_test`
- `generate_markdown_report`

Tool behavior should stay evidence-based and low impact. Reports should include
coverage, attack types, findings, and fixes.

## Evaluations

OWASP Benchmark can be used as a repeatable Web vulnerability eval target.
Start the Benchmark app separately, then run a small SPA eval set:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\eval-owasp-benchmark.ps1 `
  -BaseUrl https://localhost:8443/benchmark `
  -ExpectedResultsCsv path\to\expectedresults.csv `
  -Limit 10
```

Use `-DryRun` to generate prompts and result files without calling `spa`.

## Development

```powershell
cargo fmt --check
cargo test
```

Run with provider debug output:

```powershell
cargo run --bin spa -- --debug
```

Important paths:

```text
src/cli.rs                 CLI and agent loop
src/llm/                   provider abstraction
src/tools/                 built-in tools
src/mcp_client.rs          MCP client integration
src/agent/prompts/         system prompts
skills/                    runtime skills
```

The default system prompt is part of the agent safety boundary and is not
overridable from `.env` or CLI flags.
