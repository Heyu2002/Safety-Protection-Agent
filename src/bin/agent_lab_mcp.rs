use safety_protection_agent::agent_lab::run_stdio;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_stdio().await
}
