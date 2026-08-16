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

/// 初始化标准输出和 SQLite 双通道日志.
///
/// 标准输出使用 `RUST_LOG` 或默认 `info`; 数据库层固定为 `info,watcher=debug`.
///
/// # 参数
///
/// - `db`: 用于持久化日志行的数据库句柄.
///
/// # 返回
///
/// 全局 subscriber 安装成功时返回 `Ok(())`.
///
/// # Errors
///
/// 全局 subscriber 已被其他调用方安装时返回错误.
///
/// # 示例
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

/// 构造写入数据库的默认过滤器: 保留应用 debug, 抑制依赖噪声.
///
/// # 参数
///
/// 无.
///
/// # 返回
///
/// `info,watcher=debug` 过滤器.
///
/// # 示例
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
    /// 把当前显示时区时间写入 tracing 格式化器.
    ///
    /// # 参数
    ///
    /// - `self`: 无状态计时器.
    /// - `writer`: tracing 输出缓冲.
    ///
    /// # 返回
    ///
    /// 写入成功时返回 `Ok(())`.
    ///
    /// # Errors
    ///
    /// 底层 `write!` 失败时返回格式化错误.
    ///
    /// # 示例
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
    /// 把一条 tracing 事件写入 SQLite; 写库失败会被忽略以免打断主流程.
    ///
    /// # 参数
    ///
    /// - `self`: 持有数据库句柄的 layer.
    /// - `event`: 当前 tracing 事件.
    /// - `_ctx`: layer 上下文, 本实现未使用.
    ///
    /// # 返回
    ///
    /// 无.
    ///
    /// # 示例
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
    /// 记录字符串字段.
    ///
    /// # 参数
    ///
    /// - `field`: tracing 字段名.
    /// - `value`: 字段值.
    ///
    /// # 返回
    ///
    /// 无.
    ///
    /// # 示例
    ///
    /// ```text
    /// visitor.record_str(field, "ok");
    /// ```
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, value.to_string());
    }

    /// 记录有符号整数字段.
    ///
    /// # 参数
    ///
    /// - `field`: tracing 字段名.
    /// - `value`: 整数值.
    ///
    /// # 返回
    ///
    /// 无.
    ///
    /// # 示例
    ///
    /// ```text
    /// visitor.record_i64(field, 1);
    /// ```
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, value.to_string());
    }

    /// 记录无符号整数字段.
    ///
    /// # 参数
    ///
    /// - `field`: tracing 字段名.
    /// - `value`: 整数值.
    ///
    /// # 返回
    ///
    /// 无.
    ///
    /// # 示例
    ///
    /// ```text
    /// visitor.record_u64(field, 1);
    /// ```
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, value.to_string());
    }

    /// 记录布尔字段.
    ///
    /// # 参数
    ///
    /// - `field`: tracing 字段名.
    /// - `value`: 布尔值.
    ///
    /// # 返回
    ///
    /// 无.
    ///
    /// # 示例
    ///
    /// ```text
    /// visitor.record_bool(field, true);
    /// ```
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, value.to_string());
    }

    /// 用 `Debug` 格式记录其余字段.
    ///
    /// # 参数
    ///
    /// - `field`: tracing 字段名.
    /// - `value`: 任意 `Debug` 值.
    ///
    /// # 返回
    ///
    /// 无.
    ///
    /// # 示例
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
    /// 把一个 tracing 字段记入 `message` 或结构化字段表.
    ///
    /// # 参数
    ///
    /// - `field`: tracing 字段.
    /// - `value`: 已格式化的字段值.
    ///
    /// # 返回
    ///
    /// 无.
    ///
    /// # 示例
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
