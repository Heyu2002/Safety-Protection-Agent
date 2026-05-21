# Safety Protection Agent

[中文文档](README_CN.md)

Safety Protection Agent, or `spa`, is a Rust-based security agent for
authorized red-team validation, lab verification, and defensive vulnerability
analysis. It combines a Codex-style CLI, native model tool-calling where the
provider supports it, MCP integration, and built-in HTTP/security probes.

The project is designed for owned systems, local labs, staging environments,
and explicitly authorized testing. It does not aim to support unauthorized
access, data theft, stealth, or persistence.

## Highlights

- **Codex-style agent loop**: model output streams into the terminal, native
  tool calls are hidden from the user, and tool observations are fed back into
  the next model turn.
- **Two native model protocols**:
  - OpenAI Responses-style events: `response.output_text.delta`,
    `function_call`, `function_call_output`, `response.completed`.
  - Chat Completions-style events: `choices[].delta.content`,
    `choices[].delta.tool_calls`, `finish_reason`, `data: [DONE]`.
- **Provider fallback path**: providers without reliable native tool calls use
  a JSON fallback protocol without showing duplicate candidate answers.
- **Lazy MCP startup**: configured MCP servers are not started for normal chat;
  they connect only when a remote `mcp__...` tool is actually requested.
- **Terminal UX**: colored `user>` / `agent>` prompts, streaming assistant
  text, thinking spinner, percent progress for throughput tools, and boxed
  checklist progress for scan tools.
- **Structured security reports**: test tools report sample coverage, attack
  types, findings, and remediation guidance instead of dumping raw JSON to the
  user.

## Quick Start

Install Rust, then create a local environment file:

```powershell
Copy-Item .env.example .env
```

Edit `.env` and choose a provider. Then start the interactive CLI:

```powershell
cargo run --bin spa
```

You can also install the binaries locally on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
spa
```

Single prompt mode:

```powershell
cargo run --bin spa -- --prompt "Give me a short API security triage checklist"
```

Useful REPL commands:

```text
/help      show commands
/compact   summarize current conversation context
/clear     clear conversation history
/mcp       list configured MCP servers without starting them
/exit      quit
```

In an interactive terminal, type `/` to open the command menu or press `Tab` to
complete slash commands.

## Provider Configuration

Provider selection is controlled by `LLM_PROVIDER` in `.env`.

| Provider | Protocol | Native Tools |
| --- | --- | --- |
| `openai` | Chat Completions | Yes, when the model supports `tool_calls` |
| `openai-compatible` | Chat Completions-compatible | Yes, when the endpoint supports `tool_calls` |
| `openai-responses` | Responses API | Yes |
| `codex-chatgpt` | Codex ChatGPT Responses backend | Yes |
| `kimi` | Kimi Code-compatible Chat Completions | Yes, when supported by the endpoint |
| `moonshot` | Moonshot Chat Completions | Yes, when supported by the endpoint |
| `anthropic` | Anthropic Messages | Fallback path |
| `gemini` | Gemini Generate Content | Fallback path |
| `ollama` | Ollama Chat | Fallback path |

OpenAI-compatible example:

```env
LLM_PROVIDER=openai-compatible
OPENAI_API_KEY=your-key
OPENAI_MODEL=your-model
OPENAI_BASE_URL=https://your-provider.example.com/v1
```

OpenAI Responses example:

```env
LLM_PROVIDER=openai-responses
OPENAI_API_KEY=your-key
OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=https://api.openai.com/v1
```

Reuse a local Codex ChatGPT login:

```env
LLM_PROVIDER=codex-chatgpt
CODEX_MODEL=gpt-5.5
CODEX_CHATGPT_BASE_URL=https://chatgpt.com/backend-api/codex
```

This reads `~/.codex/auth.json`. If your shell needs a proxy to reach
`chatgpt.com`, set `HTTP_PROXY` / `HTTPS_PROXY` in `.env`.

Kimi Code / Kimi CLI subscription:

```env
LLM_PROVIDER=kimi
KIMI_API_KEY=sk-...
KIMI_MODEL=kimi-for-coding
KIMI_BASE_URL=https://api.kimi.com/coding/v1
```

Moonshot / Kimi Platform:

```env
LLM_PROVIDER=moonshot
MOONSHOT_API_KEY=sk-...
MOONSHOT_MODEL=kimi-k2.6
MOONSHOT_BASE_URL=https://api.moonshot.cn/v1
```

Ollama:

```env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
```

Some provider endpoints reject optional parameters such as `temperature`. SPA
detects this common error and retries once without `temperature`.

## MCP Integration

SPA supports Codex-style MCP configuration commands:

```powershell
spa mcp add chrome-devtools -- npx chrome-devtools-mcp@latest --isolated --no-usage-statistics
spa mcp list
```

Inside the REPL:

```text
/mcp
```

`/mcp` shows configured server names and descriptions only. It does not start
Chrome or connect to remote MCP servers.

Remote MCP tools are exposed to the model with names like:

```text
mcp__chrome-devtools__new_page
mcp__chrome-devtools__take_snapshot
```

MCP servers are lazy-connected: a regular prompt such as `你好` will not start
Chrome or any other MCP process.

SPA can also run as an MCP server:

```powershell
cargo run --bin spa-mcp
```

Long-running built-in tools emit MCP progress notifications when the MCP client
passes `_meta.progressToken`.

## Built-in Tools

| Tool | Purpose | Progress UI |
| --- | --- | --- |
| `http_load_test` | Controlled HTTP load test with request rate, concurrency, latency percentiles, status distribution, and errors. | Percent / completed count |
| `database_risk_scan` | Low-impact database risk probing for SQL error leakage, boolean response differences, and confirmed time-delay signals. Supports stateful lab flows through `verification_url`. | Checklist box |
| `http_security_headers_scan` | Checks security headers, CORS, cookie flags, cache policy, and server fingerprinting signals. | Checklist box |
| `weak_session_id_scan` | Samples generated session IDs and detects duplicates, counters, timestamp-like values, `md5(time())`, and low entropy. | Percent / sample count |
| `echo` | Minimal plumbing check for tool-call routing. | None |

Tool-based reports should explain:

- sample coverage
- attack types tested
- concrete findings and evidence
- how to fix

## Example Workflows

Database risk scan for an authorized API:

```text
user> 帮我测下 <AUTHORIZED_API_URL> 是否有数据库漏洞
agent> 请提供 HTTP 方法和实际参数。
user> GET，参数 date=<YYYY-MM-DD>，不需要鉴权
```

The agent should combine the conversation history, call `database_risk_scan`,
show checklist progress, and return a Chinese analysis instead of raw JSON.

Weak Session IDs lab:

```text
user> 帮我测试 <AUTHORIZED_LAB_URL> 的 Weak Session IDs，安全级别 medium，使用测试账号登录
```

When browser MCP is available, the agent can use it to inspect and interact
with the lab page, then use `weak_session_id_scan` to sample generated IDs.

HTTP load test:

```text
user> 帮我压测 <AUTHORIZED_LOAD_TEST_URL>
agent> 请确认请求方法、是否需要 body/headers，以及目标请求速率。
```

Load testing uses percent progress rather than checklist progress because the
user experience is throughput-oriented.

## Architecture

```text
CLI / REPL
  -> agent loop
     -> native model runtime if supported
        -> streaming assistant deltas
        -> native tool calls
        -> function/tool outputs
     -> fallback runtime otherwise
        -> JSON decision protocol
  -> local tool registry
  -> lazy MCP toolbox
```

Important modules:

```text
src/cli.rs                 CLI, REPL, agent loop, progress rendering
src/llm/                   provider abstraction and streaming/native runtime types
src/llm/providers/         provider implementations
src/tools/spec.rs          tool call/output/progress structs
src/tools/registry.rs      built-in tool registration
src/tools/handlers/        concrete tool implementations
src/mcp.rs                 SPA as an MCP server
src/mcp_client.rs          SPA as an MCP client
src/agent/prompts/         product/system prompts
```

The default system prompt is part of the agent security boundary and is not
overridable from CLI flags or `.env`.

## Development

Run the standard checks:

```powershell
cargo fmt --check
cargo check -q
cargo test -q
```

Run the CLI with provider debug info:

```powershell
cargo run --bin spa -- --debug
```

List configured MCP servers:

```powershell
cargo run --bin spa -- mcp list
```

## Safety Scope

SPA is intended for:

- authorized security validation
- local labs such as DVWA
- owned APIs and staging systems
- vulnerability triage and remediation verification
- defensive reporting and hardening guidance

It should not be used to attack systems without permission, exfiltrate data,
perform stealthy persistence, or bypass authorization outside an approved test.
