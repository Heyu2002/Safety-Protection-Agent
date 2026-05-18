# Safety-Protection-Agent

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
cargo run --bin spa-chat -- --prompt "Give me a short CVE triage checklist"
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
