//! Path dictionary CLI handlers.

use anyhow::Context;

use crate::{cli::PathCommands, db::Database};

/// Handles `dict path` subcommands.
pub fn handle(db: &Database, command: PathCommands) -> anyhow::Result<()> {
    match command {
        PathCommands::Import { file } => {
            let content = std::fs::read_to_string(&file)
                .with_context(|| format!("failed to read {}", file.display()))?;
            let mut count = 0usize;
            for line in content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
            {
                db.upsert_dict_path(line)?;
                count += 1;
            }
            println!("imported {count}");
        }
        PathCommands::Export { file } => {
            db.export_dict_paths(&file)?;
            println!("{}", file.display());
        }
        PathCommands::Query(args) => {
            for row in db.query_dict_paths(args.keyword.as_deref(), args.limit)? {
                println!("{}", row.join("\t"));
            }
        }
        PathCommands::Delete { path } => {
            db.delete_dict_path(&path)?;
            println!("deleted path: {path}");
        }
    }
    Ok(())
}
