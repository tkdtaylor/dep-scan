#[allow(dead_code)]
mod cache;
mod cli;
mod config;
#[allow(dead_code)]
mod registry;
#[allow(dead_code)]
mod types;

use std::path::Path;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command, ConfigAction};
use config::Config;

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Check {
            packages,
            registry,
            json,
        } => {
            if cli.verbose {
                eprintln!("Checking packages: {:?}", packages);
                if let Some(ref reg) = registry {
                    eprintln!("Registry: {}", reg);
                }
                if json {
                    eprintln!("Output format: JSON");
                }
            }
            println!(
                "Checking {} package(s): {}",
                packages.len(),
                packages.join(", ")
            );
            // TODO: implement actual check logic
        }
        Command::Install { packages: _ } => {
            println!("Install command is not yet implemented");
        }
        Command::Config { action } => match action {
            ConfigAction::Show => {
                let config = Config::load(cli.config.as_deref())?;
                let toml_str = config.to_toml_string()?;
                println!("{toml_str}");
            }
            ConfigAction::Init => {
                let target = Path::new(".dep-scan.toml");
                Config::write_default(target)?;
                println!("Created {}", target.display());
            }
        },
    }

    Ok(())
}
