use std::path::PathBuf;

use anyhow::{Context, Result};
use bw_sanitize::{
    load_json, load_mapping, restore_json, sanitize_json, write_json, write_mapping,
};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "bw-sanitize",
    version,
    about = "Reversibly sanitize sensitive values in Bitwarden JSON exports"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Replace sensitive strings with stable mapping tokens.
    Sanitize {
        /// Bitwarden JSON export to sanitize.
        #[arg(short, long)]
        input: PathBuf,

        /// Sanitized JSON output path.
        #[arg(short, long)]
        output: PathBuf,

        /// Mapping file path. This file contains original sensitive values.
        #[arg(short = 'm', long)]
        map: PathBuf,
    },

    /// Restore mapping tokens back to their original values.
    Restore {
        /// Sanitized JSON input path.
        #[arg(short, long)]
        input: PathBuf,

        /// Restored JSON output path.
        #[arg(short, long)]
        output: PathBuf,

        /// Mapping file created by the sanitize command.
        #[arg(short = 'm', long)]
        map: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Sanitize { input, output, map } => {
            eprintln!(
                "warning: mapping file contains original sensitive values; keep it private: {}",
                map.display()
            );

            let mut value = load_json(&input)?;
            let mapping = load_mapping(&map)?;
            let (mapping, report) = sanitize_json(&mut value, mapping);

            write_mapping(&map, &mapping)
                .with_context(|| format!("mapping was not written to {}", map.display()))?;
            write_json(&output, &value).with_context(|| {
                format!("sanitized output was not written to {}", output.display())
            })?;

            eprintln!(
                "sanitized {} values; mapping now has {} entries",
                report.replaced_values, report.total_mappings
            );
        }
        Command::Restore { input, output, map } => {
            eprintln!(
                "warning: reading mapping file with original sensitive values: {}",
                map.display()
            );

            let mut value = load_json(&input)?;
            let mapping = load_mapping(&map)?;
            let report = restore_json(&mut value, &mapping);

            write_json(&output, &value).with_context(|| {
                format!("restored output was not written to {}", output.display())
            })?;

            eprintln!("restored {} values", report.restored_values);
        }
    }

    Ok(())
}
