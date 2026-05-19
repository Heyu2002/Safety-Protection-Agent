use safety_protection_agent::mcp::run_stdio;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_stdio().await?;
    Ok(())
}
