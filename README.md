# Safety-Protection-Agent

An agent capable of scanning for different disclosed vulnerabilities.

## LLM API Adapter

This project starts with a small Rust adapter layer for mainstream model APIs.
Agent code should depend on the `LlmClient` trait instead of a vendor SDK.

Supported providers:

- `openai`: OpenAI Chat Completions API
- `openai-compatible`: any OpenAI-compatible endpoint
- `kimi`: Kimi / Moonshot API through its OpenAI-compatible endpoint
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
MOONSHOT_API_KEY=sk-...
MOONSHOT_MODEL=kimi-k2.6
MOONSHOT_BASE_URL=https://api.moonshot.cn/v1
```

For OpenAI-compatible providers, keep `LLM_PROVIDER=openai-compatible` and set
`OPENAI_BASE_URL` to the provider endpoint.

Kimi's API is OpenAI-compatible, so the Rust implementation reuses the
OpenAI-compatible provider internally while exposing clearer `MOONSHOT_*`
environment variables.
