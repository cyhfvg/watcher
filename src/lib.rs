//! Reusable application library for the watcher command-line tool.
//!
//! The binary entry point only parses process arguments and delegates to this
//! crate. Keeping operational logic here makes it directly testable and ready
//! for future embedding by another process supervisor or service wrapper.
//!
//! 公开模块覆盖配置, 守护进程, 终端仪表盘, 存储, 监测流水线和报告. 外部调用方
//! 应优先使用这些稳定路径, 而不是依赖 crate 内部的 `pub(crate)` 辅助函数.

pub mod cli;
pub mod config;
pub mod daemon;
pub mod dashboard;
pub mod db;
pub mod dict;
pub mod import;
pub mod local_time;
pub mod logging;
pub mod models;
pub mod monitor;
pub mod notify;
pub mod report;
