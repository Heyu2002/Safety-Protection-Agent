# Safety Protection Agent

[中文文档](README_CN.md)

Safety Protection Agent (`spa`) is a Rust-based terminal security agent for
authorized defensive testing, local lab validation, and repeatable vulnerability
evaluation. It combines a Codex-style interactive loop, model tool calling, MCP
integration, runtime skills, and built-in low-impact security checks.

`spa` is intended only for owned systems, local labs, and explicitly authorized
targets. Do not use it for unauthorized access, stealth, persistence, data theft,
or bypassing permission boundaries.

## Quick Start

Run directly from the repository:

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

## Configuration

Configure the model provider in `.env`. Supported providers and common relay
examples are documented in `.env.example`.

Minimal local/default configuration:

```env
LLM_PROVIDER=codex-chatgpt
```

OpenAI-compatible or relay configuration:

```env
LLM_PROVIDER=openai-responses
LLM_API_KEY=your-key
LLM_MODEL=your-model
LLM_BASE_URL=https://provider.example.com/v1
```

If a Chat Completions-compatible relay rejects native tool parameters, disable
native tool payloads:

```env
LLM_NATIVE_TOOLS=false
```

To allow completed Markdown reports to be written by the report tool, set:

```env
SPA_AGENT_REPORT_DIR=reports
```

Reports are written only when the model explicitly calls
`generate_markdown_report` after a report is complete.

## MCP Integration

Register MCP servers with the CLI:

```powershell
spa mcp add chrome-devtools -- npx chrome-devtools-mcp@latest --isolated --no-usage-statistics
spa mcp list
```

Configured MCP tools are exposed to the model at the beginning of each agent
turn. The model decides whether to call them.

`spa` can also run as an MCP server:

```powershell
cargo run --bin spa-mcp
```

The agent red-team lab MCP server is separate:

```powershell
cargo run --bin spa-agent-lab-mcp
```

## Runtime Skills

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

## Built-in Tools

Built-in tools focus on evidence-based, low-impact checks and report generation:

- `http_security_headers_scan`
- `database_risk_scan`
- `xss_risk_scan`
- `weak_session_id_scan`
- `http_load_test`
- `generate_markdown_report`

Formal reports should include scope, coverage, attack types, findings, evidence,
and fixes.

## Evaluation Snapshot

The included OWASP Benchmark comparison covers 30 common cases from the 2,740
case truth set. Source report path in this workspace:
`target/owasp-benchmark-agent-comparison-30/comparison.md`.

Generated at: `2026-05-29T19:51:11.1365400+08:00`

| Agent | Cases | Correct | TP | FP | TN | FN | Inconclusive | Avg seconds/case | Accuracy | Estimated full hours | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| spa | 30 | 22 | 15 | 2 | 7 | 2 | 4 | 71.4 | 0.7333 | 54.3 | 0.8824 |
| codex | 30 | 23 | 14 | 1 | 9 | 2 | 4 | 394.3 | 0.7667 | 300.1 | 0.875 |

## OWASP Benchmark Evaluation

OWASP Benchmark can be used as a repeatable web vulnerability evaluation target.
Start the Benchmark app separately, then run a small SPA evaluation set:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\eval-owasp-benchmark.ps1 `
  -BaseUrl https://localhost:8443/benchmark `
  -ExpectedResultsCsv path\to\expectedresults.csv `
  -Limit 10
```

Use `-DryRun` to generate prompts and result files without calling `spa`.

## Development

Run formatting and tests before submitting code changes:

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
src/llm/                   Provider abstraction
src/tools/                 Built-in tools
src/mcp_client.rs          MCP client integration
src/agent/prompts/         System prompts
skills/                    Runtime skills
scripts/                   Install, skill, and evaluation scripts
target/                    Generated build and evaluation outputs
```

The default system prompt is part of the agent safety boundary and is not
overridable from `.env` or CLI flags.
