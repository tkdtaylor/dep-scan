use anyhow::Result;

fn main() -> Result<()> {
    println!("dep-scan v{}", env!("CARGO_PKG_VERSION"));
    Ok(())
}
