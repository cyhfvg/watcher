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
    fmt::{self, format::Writer, time::FormatTime},
    layer::Context,
    prelude::*,
};

use crate::{db::Database, local_time};

/// Initializes dual-channel logging to stdout and SQLite.
///
/// Stdout uses `RUST_LOG` or a default of `info`; the database layer is fixed
/// to `info,watcher=debug`.
///
/// # Arguments
///
/// - `db`: database handle used to persist log rows.
///
/// # Returns
///
/// `Ok(())` after the global subscriber is installed.
///
/// # Errors
///
/// Returns an error if another caller has already installed a global
/// subscriber.
///
/// # Examples
///
/// ```no_run
/// # use watcher::{db::Database, logging};
/// # fn demo(db: &Database) -> anyhow::Result<()> {
/// logging::init(db)?;
/// # Ok(())
/// # }
/// ```
pub fn init(db: &Database) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(fmt::layer().with_timer(LocalTimer).with_filter(filter))
        .with(DbLogLayer { db: db.clone() }.with_filter(db_log_filter()))
        .try_init()?;
    Ok(())
}

/// Builds the default database log filter: keep app debug, drop dependency
/// noise.
///
/// # Arguments
///
/// none
///
/// # Returns
///
/// `info,watcher=debug` filter.
///
/// # Examples
///
/// ```text
/// let filter = db_log_filter();
/// ```
fn db_log_filter() -> EnvFilter {
    EnvFilter::new("info,watcher=debug")
}

/// Configured display timezone timer for human-facing stdout logs.
struct LocalTimer;

impl FormatTime for LocalTimer {
    /// Writes the current display-timezone time into the tracing formatter.
    ///
    /// # Arguments
    ///
    /// - `self`: stateless timer.
    /// - `writer`: tracing output buffer.
    ///
    /// # Returns
    ///
    /// `Ok(())` when the write succeeds.
    ///
    /// # Errors
    ///
    /// Returns a formatting error if the underlying `write!` fails.
    ///
    /// # Examples
    ///
    /// ```text
    /// write!(writer, "{}", local_time::now_rfc3339())?;
    /// ```
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
    /// Writes one tracing event to SQLite; write failures are ignored so the
    /// main workflow is not interrupted.
    ///
    /// # Arguments
    ///
    /// - `self`: layer that holds the database handle.
    /// - `event`: current tracing event.
    /// - `_ctx`: layer context, unused by this implementation.
    ///
    /// # Returns
    ///
    /// none
    ///
    /// # Examples
    ///
    /// ```text
    /// layer.on_event(&event, ctx);
    /// ```
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
    /// Records a string field.
    ///
    /// # Arguments
    ///
    /// - `field`: tracing field name.
    /// - `value`: field value.
    ///
    /// # Returns
    ///
    /// none
    ///
    /// # Examples
    ///
    /// ```text
    /// visitor.record_str(field, "ok");
    /// ```
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }

    /// Records a signed integer field.
    ///
    /// # Arguments
    ///
    /// - `field`: tracing field name.
    /// - `value`: integer value.
    ///
    /// # Returns
    ///
    /// none
    ///
    /// # Examples
    ///
    /// ```text
    /// visitor.record_i64(field, 1);
    /// ```
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    /// Records an unsigned integer field.
    ///
    /// # Arguments
    ///
    /// - `field`: tracing field name.
    /// - `value`: integer value.
    ///
    /// # Returns
    ///
    /// none
    ///
    /// # Examples
    ///
    /// ```text
    /// visitor.record_u64(field, 1);
    /// ```
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    /// Records a boolean field.
    ///
    /// # Arguments
    ///
    /// - `field`: tracing field name.
    /// - `value`: boolean value.
    ///
    /// # Returns
    ///
    /// none
    ///
    /// # Examples
    ///
    /// ```text
    /// visitor.record_bool(field, true);
    /// ```
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    /// Records remaining fields with `Debug` formatting.
    ///
    /// # Arguments
    ///
    /// - `field`: tracing field name.
    /// - `value`: any `Debug` value.
    ///
    /// # Returns
    ///
    /// none
    ///
    /// # Examples
    ///
    /// ```text
    /// visitor.record_debug(field, &error);
    /// ```
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let mut rendered = String::new();
        let _ = write!(&mut rendered, "{value:?}");
        self.record_value(field, rendered);
    }
}

impl LogVisitor {
    /// Records one tracing field into `message` or the structured field map.
    ///
    /// # Arguments
    ///
    /// - `field`: tracing field.
    /// - `value`: already-formatted field value.
    ///
    /// # Returns
    ///
    /// none
    ///
    /// # Examples
    ///
    /// ```text
    /// visitor.record_value(field, value.to_string());
    /// ```
    fn record_value(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.insert(field.name().to_string(), value);
        }
    }
}
