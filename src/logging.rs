//! Tracing setup with SQLite-backed log persistence.

use std::{
    collections::BTreeMap,
    fmt::{self as std_fmt, Write},
};

use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{
    EnvFilter, Layer,
    filter::LevelFilter,
    fmt::{self, format::Writer, time::FormatTime},
    layer::Context,
    prelude::*,
};

use crate::{db::Database, local_time};

/// Initializes stdout and SQLite logging.
pub fn init(db: &Database) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(fmt::layer().with_timer(LocalTimer).with_filter(filter))
        .with(DbLogLayer { db: db.clone() }.with_filter(LevelFilter::DEBUG))
        .try_init()?;
    Ok(())
}

/// Configured display timezone timer for human-facing stdout logs.
struct LocalTimer;

impl FormatTime for LocalTimer {
    fn format_time(&self, writer: &mut Writer<'_>) -> std_fmt::Result {
        write!(writer, "{}", local_time::now_rfc3339())
    }
}

/// Tracing layer that writes events to the watcher SQLite database.
struct DbLogLayer {
    /// Database handle used for writing log records.
    db: Database,
}

impl<S> Layer<S> for DbLogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = LogVisitor::default();
        event.record(&mut visitor);

        let message = visitor
            .message
            .unwrap_or_else(|| metadata.name().to_string());
        visitor.fields.insert(
            "file".to_string(),
            metadata.file().unwrap_or("").to_string(),
        );
        visitor.fields.insert(
            "line".to_string(),
            metadata
                .line()
                .map(|line| line.to_string())
                .unwrap_or_default(),
        );
        let fields = serde_json::to_string(&visitor.fields).ok();

        // Logging must never break the main workflow, so database write errors are ignored here.
        let _ = self.db.add_log(
            metadata.level().as_str(),
            metadata.target(),
            &message,
            fields.as_deref(),
        );
    }
}

/// Field visitor that separates the main `message` from structured fields.
#[derive(Default)]
struct LogVisitor {
    /// Main textual log message.
    message: Option<String>,
    /// Additional structured fields.
    fields: BTreeMap<String, String>,
}

impl Visit for LogVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut rendered = String::new();
        let _ = write!(&mut rendered, "{value:?}");
        self.record_value(field, rendered);
    }
}

impl LogVisitor {
    /// Records one tracing field.
    fn record_value(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.insert(field.name().to_string(), value);
        }
    }
}
