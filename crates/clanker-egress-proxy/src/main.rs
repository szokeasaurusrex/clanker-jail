use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    clanker_egress_proxy::run().await
}
