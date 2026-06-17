use anyhow::Result;
use xminecraft::cli;

#[tokio::main]
async fn main() -> Result<()> {
    cli::run().await
}
