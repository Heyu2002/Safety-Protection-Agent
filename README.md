# Safety Protection Agent

[Chinese documentation](README_CN.md)

Safety Protection Agent (`spa`) is a Rust terminal agent for authorized
defensive testing, local lab validation, and repeatable vulnerability
evaluation. It combines a Codex-style agent loop, model tool calling, MCP
integration, runtime skills, context compaction, and built-in low-impact
security tools.

Use `spa` only on owned systems, local labs, benchmark targets, staging
environments, or explicitly authorized scopes. Do not use it for unauthorized
access, stealth, persistence, data theft, or bypassing permission boundaries.

## Current Evaluation Summary

Local OWASP Benchmark sample summary, updated on 2026-06-02:

- Combined sample: 60 OWASP Benchmark case rows
- Source sets: previous summary 30 + current fully random 30
- Current random seed: `849023657`
- Duplicate case IDs between the two sets: 0
- Previous comparison report: `target/owasp-benchmark-agent-comparison-30/comparison.json`
- Current case manifest: `target/owasp-benchmark-random-30-current/cases-random-30.json`
- Current SPA score: `target/owasp-benchmark-random-30-current/spa-after-tool-fixes-30-final/score.json`
- Current Codex comparison score: `target/owasp-benchmark-random-30-current/codex-jobs-3/score.json`

The aggregate below combines the previous 30-case comparison
(`spa` 22/30, `codex` 23/30) with the current random 30-case comparison
(`spa` 30/30, `codex` 29/30). Accuracy is strict accuracy over all sampled
rows; inconclusive results are not counted as correct.

| Runner | Cases | Correct | TP | FP | TN | FN | Inconclusive | Execution errors | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| spa | 60 | 52 | 35 | 2 | 17 | 2 | 4 | 0 | 0.8667 | 0.9459 | 0.9459 | 0.9459 |
| codex | 60 | 52 | 34 | 2 | 18 | 2 | 4 | 0 | 0.8667 | 0.9444 | 0.9444 | 0.9444 |

The current random 30-case run reflects the latest tool fixes for:

- SQLi and trust-boundary semantic flow through request arrays, headers,
  cookies, `StringBuilder`, lists/maps, inner methods, inline conditionals, and
  Spring `JDBCtemplate` sinks.
- Crypto semantic detection for `Cipher.getInstance(variable)` defaults and
  weak `KeyGenerator` algorithms.
- Weak-randomness classification that distinguishes `SecureRandom` instances
  from `java.util.Random` declaration types.
- Path-traversal active-probe confirmation that requires payload-controlled
  file behavior rather than a fixed file-operation banner.

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

Automatic context compaction is enabled by default. The agent estimates the
next request size and compacts conversation history at 90% of the configured
context window.

```env
LLM_AUTO_COMPACT=true
LLM_CONTEXT_WINDOW=128000
LLM_AUTO_COMPACT_PERCENT=90
```

Set an explicit lower limit when using smaller local or relay models:

```env
LLM_AUTO_COMPACT_TOKEN_LIMIT=32768
```

To allow completed Markdown reports to be written by the report tool:

```env
SPA_AGENT_REPORT_DIR=reports
```

Reports are written only when the model explicitly calls
`generate_markdown_report` after a report is complete.

## Built-in Tools

Built-in tools focus on evidence-based, bounded checks:

- `http_active_probe_scan`
- `http_security_headers_scan`
- `database_risk_scan`
- `xss_risk_scan`
- `weak_session_id_scan`
- `java_injection_semantic_scan`
- `java_crypto_semantic_scan`
- `java_randomness_semantic_scan`
- `http_load_test`
- `generate_markdown_report`

The Java semantic tools are primarily used for benchmark and lab cases where
black-box responses are intentionally collapsed or too generic. They inspect
source-level evidence for SQL/LDAP/XPath injection, trust-boundary flow, weak
crypto, weak hashing, and weak randomness.

## MCP Integration

Register MCP servers with the CLI:

```powershell
spa mcp add chrome-devtools -- npx chrome-devtools-mcp@latest --isolated --no-usage-statistics
spa mcp list
```

Configured MCP tools are exposed to the model at the beginning of each agent
turn. The model decides whether to call them.

Run `spa` as an MCP server:

```powershell
cargo run --bin spa-mcp
```

Run the agent red-team lab MCP server:

```powershell
cargo run --bin spa-agent-lab-mcp
```

## Runtime Skills

Runtime skills live in `skills/`. The host exposes the skill catalog to the
model, the model selects relevant skills, and selected `SKILL.md` bodies are
added to the agent context.

Included skills:

- `web-vulnerability-discovery`
- `isolated-web-security-assessment`
- `agent-redteam-lab`

Create a new skill:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-skill.ps1 -Name skill-name -Description "Use when ..."
```

## OWASP Benchmark Evaluation

Start OWASP Benchmark separately, then run a score pass:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\eval-owasp-benchmark-score.ps1 `
  -BaseUrl https://localhost:8443/benchmark `
  -CasesPath target\owasp-benchmark-random-30-current\cases-random-30.json `
  -OutputDir target\owasp-benchmark-random-30-current\spa `
  -Runner spa `
  -Limit 0 `
  -ReportOutput off
```

Use `-Runner codex` to compare Codex CLI behavior. Codex runs can be parallelized
and resumed with partial result files:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\eval-owasp-benchmark-score.ps1 `
  -BaseUrl https://localhost:8443/benchmark `
  -CasesPath target\owasp-benchmark-random-30-current\cases-random-30.json `
  -OutputDir target\owasp-benchmark-random-30-current\codex-jobs-3 `
  -Runner codex `
  -Jobs 3 `
  -Limit 0 `
  -ReportOutput off
```

The scoring script writes:

- `score.json`
- `score.csv`
- `tool-coverage-plan.md`
- per-case logs
- resumable `partial-results/*.result.json`

Use `-DryRun` to generate prompts and result files without calling the runner.

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
