use clap::Parser;
use safety_protection_agent::llm::{ChatMessage, CompletionRequest, client_from_env};

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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let args = Args::parse();
    let client = client_from_env()?;

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
