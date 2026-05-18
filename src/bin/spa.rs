use safety_protection_agent::cli::run_chat_cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_chat_cli(true).await
}
