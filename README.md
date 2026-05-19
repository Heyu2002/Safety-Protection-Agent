# Safety-Protection-Agent

[中文文档](README_CN.md)

An agent capable of scanning for different disclosed vulnerabilities.

## LLM API Adapter

This project starts with a small Rust adapter layer for mainstream model APIs.
Agent code should depend on the `LlmClient` trait instead of a vendor SDK.

Supported providers:

- `openai`: OpenAI Chat Completions API
- `openai-compatible`: any OpenAI-compatible endpoint
- `openai-responses`: OpenAI Responses API endpoint
- `codex-chatgpt`: local Codex ChatGPT login through `~/.codex/auth.json`
- `kimi`: Kimi Code / Kimi CLI subscription API
- `moonshot`: Moonshot / Kimi Platform API
- `anthropic`: Anthropic Messages API
- `gemini`: Google Gemini Generate Content API
- `ollama`: local Ollama chat API

### Quick Start

```powershell
Copy-Item .env.example .env
```

Edit `.env`, then run:

```powershell
cargo run --bin spa
```

The `spa` launcher starts an interactive CLI session with conversation history.
For one-click local installation on Windows, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

The install script adds `%USERPROFILE%\.cargo\bin` to the current user's PATH
when needed, installs the binaries, and then `spa` can be started directly:

```powershell
spa
```

You can also send a single prompt:

```powershell
cargo run --bin spa -- --prompt "Give me a short CVE triage checklist"
```

Inside the REPL, use `/compact` to summarize the current context, `/clear` to
reset context, and `/exit` to quit.
When running in an interactive terminal, type `/` to open the command menu or
press Tab to complete slash commands.

The lower-level `spa-chat` binary is still available:

```powershell
cargo run --bin spa-chat -- --repl
```

### MCP Server

`spa-mcp` exposes the built-in tools over stdio using the MCP data model from
the `rmcp` crate:

```powershell
cargo run --bin spa-mcp
```

Available tools include:

- `http_load_test`: paced HTTP load testing with progress callbacks and
  structured metrics.
- `database_risk_scan`: defensive database attack-surface probing for SQL
  error leakage, boolean-difference signals, and optional short time-delay
  behavior.
- `echo`: tool-call plumbing check.

Long-running tool calls support MCP progress notifications when the client
passes `_meta.progressToken`.

### Tool Layout

The tool package follows the Codex-style split:

- `src/tools/spec.rs`: shared tool call, output, progress, and schema structs.
- `src/tools/registry.rs`: tool registration and lookup.
- `src/tools/router.rs`: tool-call routing through the registry.
- `src/tools/handlers.rs` and `src/tools/handlers/`: concrete tool handlers.

Add new tools under `src/tools/handlers/`, export them from
`src/tools/handlers.rs`, then register them in `ToolRegistry::with_builtins`.

### Agent System Prompt

The default Safety Protection Agent system prompt lives in
`src/agent/prompts/default.md`. The compaction prompt lives in
`src/agent/prompts/compact.md`. `src/agent/prompt.rs` only exposes these
Markdown prompts to Rust with `include_str!`.

The prompt defines the agent's product identity, defensive security scope,
operating style, context rules, and safety boundaries. Providers stay generic
and only send requests to model APIs.

The system prompt is not configurable from CLI arguments or `.env`, because it
is part of the agent's security boundary. Change it in code when the product
behavior intentionally changes.

### Skills

Codex-style skill scaffolding lives under `skills/`. Shared conventions are in
`skills/CONVENTIONS.md`, and reusable templates live in `skills/templates/`.

Create a new skill scaffold with:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-skill.ps1 -Name skill-name -Description "Use when ..."
```

### Library Usage

```rust
use safety_protection_agent::llm::{
    ChatMessage, CompletionRequest, LlmClient, client_from_env,
};

#[tokio::main]
async fn main() -> safety_protection_agent::llm::Result<()> {
    dotenvy::dotenv().ok();

    let client = client_from_env()?;
    let response = client
        .complete(CompletionRequest::new(vec![
            ChatMessage::system("You are a security analysis assistant."),
            ChatMessage::user("Summarize CVE-2024-3094 in one paragraph."),
        ]))
        .await?;

    println!("{}", response.content);
    Ok(())
}
```

### Environment Variables

```text
LLM_PROVIDER=kimi
KIMI_API_KEY=sk-...
KIMI_MODEL=kimi-for-coding
KIMI_BASE_URL=https://api.kimi.com/coding/v1
```

For OpenAI-compatible providers, keep `LLM_PROVIDER=openai-compatible` and set
`OPENAI_BASE_URL` to the provider endpoint.

For a custom relay or proxy, use the same OpenAI-compatible adapter:

```text
LLM_PROVIDER=openai-compatible
OPENAI_API_KEY=your-proxy-key
OPENAI_MODEL=your-proxy-model
OPENAI_BASE_URL=https://your-proxy.example.com/v1
```

The relay should expose `POST /v1/chat/completions`.

If your relay only supports OpenAI Responses API, use:

```text
LLM_PROVIDER=openai-responses
OPENAI_API_KEY=your-proxy-key
OPENAI_MODEL=your-proxy-model
OPENAI_BASE_URL=https://your-proxy.example.com/v1
```

The relay should expose `POST /v1/responses`.

To reuse a local Codex ChatGPT login, use:

```text
LLM_PROVIDER=codex-chatgpt
CODEX_MODEL=gpt-5.5
CODEX_CHATGPT_BASE_URL=https://chatgpt.com/backend-api/codex
```

This reads `~/.codex/auth.json` and calls `POST /responses` on the Codex
ChatGPT backend. It requires your shell network environment to reach
`chatgpt.com`.

Kimi Code / Kimi CLI subscriptions use the `api.kimi.com` account system:

```text
LLM_PROVIDER=kimi
KIMI_API_KEY=sk-...
KIMI_MODEL=kimi-for-coding
KIMI_BASE_URL=https://api.kimi.com/coding/v1
```

Moonshot / Kimi Platform API keys use a separate account system:

```text
LLM_PROVIDER=moonshot
MOONSHOT_API_KEY=sk-...
MOONSHOT_MODEL=kimi-k2.6
MOONSHOT_BASE_URL=https://api.moonshot.cn/v1
```
