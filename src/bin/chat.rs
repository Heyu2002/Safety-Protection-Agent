use clap::Parser;
use safety_protection_agent::llm::{ChatMessage, CompletionRequest, LlmConfig, client_from_config};

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long)]
    prompt: String,

    #[arg(long)]
    system: Option<String>,

    #[arg(long)]
    temperature: Option<f32>,

    #[arg(long)]
    max_tokens: Option<u32>,

    #[arg(long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let args = Args::parse();
    let config = LlmConfig::from_env()?;
    if args.debug {
        eprintln!(
            "provider={:?}, model={}, base_url={}",
            config.provider,
            config.model,
            config.base_url.as_deref().unwrap_or("")
        );
    }
    let client = client_from_config(config)?;

    let mut messages = Vec::new();
    if let Some(system) = args.system {
        messages.push(ChatMessage::system(system));
    }
    messages.push(ChatMessage::user(args.prompt));

    let mut request = CompletionRequest::new(messages);
    if let Some(temperature) = args.temperature {
        request = request.with_temperature(temperature);
    }
    if let Some(max_tokens) = args.max_tokens {
        request = request.with_max_tokens(max_tokens);
    }

    let response = client.complete(request).await?;
    println!("{}", response.content);

    Ok(())
}
