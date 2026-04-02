mod cli;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command, ConfigAction};

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
                if let Some(ref path) = cli.config {
                    println!("Config path: {}", path.display());
                } else {
                    println!("No config file specified; using defaults.");
                }
                // TODO: implement config show
            }
            ConfigAction::Init => {
                println!("Initializing configuration...");
                // TODO: implement config init
            }
        },
    }

    Ok(())
}
