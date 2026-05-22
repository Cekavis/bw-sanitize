use std::path::PathBuf;

use anyhow::{Context, Result};
use bw_sanitize::{
    AnalyzeOptions, MergeApplyOptions, analysis_to_markdown, analyze_merge_candidates,
    apply_recommended_merges, load_json, load_mapping, restore_json, sanitize_json, write_json,
    write_mapping,
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

    /// Find conservative merge candidates in a sanitized Bitwarden JSON export.
    Analyze {
        /// Sanitized Bitwarden JSON input path.
        #[arg(short, long)]
        input: PathBuf,

        /// Markdown report output path.
        #[arg(short, long)]
        output: PathBuf,

        /// Optional machine-readable JSON report output path.
        #[arg(long)]
        json: Option<PathBuf>,
    },

    /// Apply high-confidence merge candidates to a sanitized Bitwarden JSON export.
    Merge {
        /// Sanitized Bitwarden JSON input path.
        #[arg(short, long)]
        input: PathBuf,

        /// Merged sanitized JSON output path.
        #[arg(short, long)]
        output: PathBuf,

        /// Extra comma-separated URI group to merge when all matched items share a credential.
        #[arg(long = "manual-group", value_name = "URI[,URI...]")]
        manual_groups: Vec<String>,
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
        Command::Analyze {
            input,
            output,
            json,
        } => {
            let value = load_json(&input)?;
            let analysis = analyze_merge_candidates(&value, AnalyzeOptions::default());
            let markdown = analysis_to_markdown(&analysis);

            std::fs::write(&output, markdown).with_context(|| {
                format!("analysis report was not written to {}", output.display())
            })?;

            if let Some(json_output) = json {
                let bytes =
                    serde_json::to_vec_pretty(&analysis).context("failed to serialize analysis")?;
                std::fs::write(&json_output, bytes).with_context(|| {
                    format!(
                        "JSON analysis report was not written to {}",
                        json_output.display()
                    )
                })?;
            }

            eprintln!(
                "found {} high-confidence merge groups, {} password conflict groups, {} review groups",
                analysis.summary.high_confidence_merge_groups,
                analysis.summary.password_conflict_groups,
                analysis.summary.review_groups
            );
        }
        Command::Merge {
            input,
            output,
            manual_groups,
        } => {
            let mut value = load_json(&input)?;
            let options = MergeApplyOptions {
                manual_uri_groups: parse_manual_groups(&manual_groups),
            };
            let report = apply_recommended_merges(&mut value, options);

            write_json(&output, &value).with_context(|| {
                format!("merged output was not written to {}", output.display())
            })?;

            eprintln!(
                "merged {} groups; removed {} items; appended {} uris, {} fields, {} password-history entries, {} fido2 credentials, {} collection ids; preserved {} scalar values as fields; manual groups matched {}, unmatched {}; skipped {} conflict groups",
                report.merged_groups,
                report.removed_items,
                report.appended_login_uris,
                report.appended_fields,
                report.appended_password_history_entries,
                report.appended_fido2_credentials,
                report.appended_collection_ids,
                report.preserved_scalar_values_as_fields,
                report.manual_groups_matched,
                report.manual_groups_unmatched,
                report.skipped_conflict_groups
            );
        }
    }

    Ok(())
}

fn parse_manual_groups(groups: &[String]) -> Vec<Vec<String>> {
    groups
        .iter()
        .map(|group| {
            group
                .split(',')
                .map(str::trim)
                .filter(|uri| !uri.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|group| group.len() > 1)
        .collect()
}
