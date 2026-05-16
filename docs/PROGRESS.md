# watcher 实现进度记录

## 2026-05-15 初始工程化实现

本阶段从一个仅包含 `Hello, world!` 的 Rust 项目开始，完成了资产监控命令行工具的第一版可运行骨架。实现重点是先建立长期维护所需的模块边界、数据库结构、配置体系、任务批次模型和可扩展扫描流程。

## 已完成能力

- 初始化工程依赖：引入 `clap`、`tokio`、`rusqlite`、`umya-spreadsheet`、`reqwest`、`lettre`、`zip`、`serde` 等依赖。
- 静态化友好设计：HTTP 和 SMTP 使用 `rustls`，SQLite 使用 `rusqlite/bundled`，避免 OpenSSL 依赖。
- 默认路径约定：配置文件默认 `~/.config/watcher/watcher.yml`，数据库默认 `~/.config/watcher/watcher.db`。
- CLI 子命令：实现 `init`、`baseline`、`system`、`daemon run`、`task`、`log`、`dict path`、`url`、`port`、`ip`、`name`、`report`。
- CLI 配置入口：移除自定义 `--config` 参数，统一使用默认配置路径；新增 `--example` 输出示例配置。
- Daemon 运行方式：`daemon run` 默认后台启动，不占据终端；`daemon run --foreground` 用于前台调试。
- 日志持久化：新增 `logs` 表和 SQLite tracing layer，运行日志会写入数据库；提供 `log query`、`log export`、`log clear`。
- 邮件配置：新增 `smtp_security`，支持 `auto`、`tls`、`starttls`、`none`；`auto` 会将 465 映射为隐式 TLS，将 587 映射为 STARTTLS。
- 邮件排障：邮件发送失败日志增加 SMTP 配置摘要、附件路径和完整错误链，便于通过 `log query --keyword email` 排查。
- 配置系统：实现 YAML 配置加载、首次运行自动生成默认配置、`~` 路径展开、目录自动创建。
- DNS 解析配置：新增 `probe.dns_servers`，默认空数组使用系统 DNS；配置后域名解析任务使用指定 DNS 服务器。
- 端口扫描配置：`probe.scan_ports` 支持端口列表，也支持 `full`/`all` 全端口扫描。
- 端口扫描并发：新增 `scan_ip_concurrency` 和 `scan_port_concurrency_per_ip`，端口扫描实际并发为二者乘积；默认 TCP 超时调整为 `2000ms`。
- 端口扫描顺序：每个 IP 扫描前随机化端口顺序，避免固定递增端口序列。
- SQLite 数据库：实现迁移和核心表结构，包括 `systems`、`domains`、`ip_addresses`、`ports`、`urls`、`dict_paths`、`batches`、`alerts`、`vulnerabilities`、`pending_work`、`logs`。
- Excel 导入：支持字段 `id,system,servername,real_ip,servername_bind_ip,port,url`，忽略 `id`，按业务系统归并资产。
- 资产管理：`system` 子命令支持业务系统新增、查询、导出、删除和重命名；普通 URL、端口、IP、域名子命令支持导出、查询、删除；基准资产通过 `baseline` 子命令导入和细粒度管理。
- path 字典管理：支持目录枚举字典的导入、导出、查询、删除。
- 批次调度：实现单批次执行和 daemon 循环调度，批次超出调度间隔时请求停止。
- 任务 1 域名解析：对所有域名解析，更新绑定 IP，记录 DNS 变化告警。
- 任务 2 端口扫描：对实际 IP 执行慢速 TCP 探测，记录端口开放/关闭变化。
- 任务 3 服务指纹：对开放端口识别 HTTP/HTTPS 和基础 banner。
- 任务 4 Web 目录枚举：对 Web 服务按 path 字典慢速枚举，过滤伪 200 响应，同时尝试 `ip:port` 和同业务系统下 `name:port` 访问，并尝试从 HTML/JS 中提取入口。
- 任务 5 轻量漏洞扫描：实现首个 POC `webpack_sourcemap_disclosure`，检测 JS sourcemap 标记和可访问 `.map` 文件。
- WAF 缓解：配置化 `per_target_delay_ms`，目录枚举和漏洞扫描在请求间加入延时。
- 未完成任务补偿：增加 `pending_work` 表，目录枚举和漏洞扫描会优先处理上一批次遗留目标。
- 任务 6 报表打包：生成 `summary.md`，并按 `report.format` 输出 `xlsx`、`json` 或 `csv` 明细后打包 zip；默认 `xlsx` 便于人工查看和表格筛选。
- 报告摘要增强：`summary.md` 增加新增开放端口、关闭端口、DNS 解析变化、漏洞数量、漏洞类型分布和重点关注表格。
- 基准资产标记：新增 `is_baseline` 字段，Excel 导入和 `baseline` 资产导入的数据默认标记为基准资产。
- 基准资产管理：新增顶层 `baseline` 动作式子命令，提供 `baseline add|import|export|query|delete|unmark --asset-type <url|port|ip|name>`，Excel 导入使用 `baseline import --asset-type excel`；普通 `url/port/ip/name` 子命令不再承载基准标记操作。
- 基准对比报表：`summary.md` 增加基准/非基准 URL、开放端口数量与示例，明细报表增加 `baseline` 列。
- 报表格式配置：新增 `report.format`，默认 `xlsx`，额外支持 `json` 和 `csv`。
- 报表可读性：明细报表统一输出 `system_name`，不再展示不适合人工阅读的 `system_id`。
- XLSX 读写：统一使用 `umya-spreadsheet` 负责 Excel 导入、`details.xlsx` 写入和回读测试，移除重复的 `calamine` 依赖。
- 日志等级：`log query/export` 使用明确的 `--level error|warn|info|debug|trace` 过滤，数据库日志记录 DEBUG 及以上事件。
- 任务 7 邮件通知：按配置发送监控摘要，并附带 zip 报告。
- 文档：新增 `README.md` 和 `examples/watcher.yml`，记录使用方式、导入字段、任务链路、数据库设计和构建方式。
- 测试：新增配置、数据库、Excel 端口解析、Web 过滤、sourcemap POC 单元测试。

## 当前模块划分

- `src/main.rs`：CLI 入口和子命令分发。
- `src/cli/`：命令行参数定义和资产管理命令处理。
- `src/config/`：配置模型、默认配置、路径处理。
- `src/daemon.rs`：后台进程启动逻辑。
- `src/db/`：SQLite 迁移和数据访问层。
- `src/import/`：Excel 资产导入。
- `src/logging.rs`：tracing 日志初始化和 SQLite 日志落库。
- `src/dict/`：path 字典管理。
- `src/models/`：跨模块共享数据结构。
- `src/monitor/`：DNS、端口扫描、指纹、目录枚举、漏洞扫描、调度器。
- `src/report/`：报表生成和 zip 打包。
- `src/notify/`：邮件通知。

## 数据库设计说明

当前数据库以业务系统 `systems` 为聚合根：

- `domains` 保存域名、绑定 IP、最近解析结果。
- `ip_addresses` 保存实际 IP 和解析得到的 IP，使用 `source` 区分 `imported`、`manual`、`resolved`。
- `ports` 保存系统/IP/端口维度的状态、协议、指纹、Web 标识。
- `urls` 保存导入 URL、Web 枚举发现 URL、JS 发现 URL 和漏洞关联 URL。
- `domains`、`ip_addresses`、`ports`、`urls` 使用 `is_baseline` 区分导入基准资产和扫描/枚举发现资产，报表以此作为主要比较源。
- `alerts` 保存 DNS、端口、漏洞等变化事件，便于批次对比和报表汇总。
- `vulnerabilities` 保存轻量 POC 命中结果。
- `batches` 保存周期任务批次状态和报告路径。
- `pending_work` 保存批次被停止后需要优先补偿的目标。
- `logs` 保存应用运行日志，包括时间、级别、目标模块、消息和结构化字段。

## 已验证命令

```bash
cargo check
cargo clippy -- -D warnings
cargo test
cargo run -- --example
cargo run -- --help
cargo run -- log query --limit 5
```

验证结果：

- `cargo check` 通过。
- `cargo clippy -- -D warnings` 通过。
- `cargo test` 通过，当前单元测试全部成功。
- 默认配置初始化逻辑保留，会创建 `~/.config/watcher/watcher.yml` 和 `~/.config/watcher/watcher.db`。
- `--example` 能输出示例配置且不会初始化数据库。
- `log query` 可查询 SQLite 中的日志记录。
- CLI help 输出正常。

## 后续建议

- 增加真实 Excel 文件的集成测试。
- 增加 HTTP mock 服务测试目录枚举和 sourcemap POC。
- 增加 daemon 后台化方式，例如 systemd service 示例或 PID 文件管理。
- 增加更细粒度的任务状态表，展示每个任务阶段的进度。
- 增加报告中的差异对比章节，例如新增端口、关闭端口、新增 URL、DNS 变化、漏洞列表。
- 增加 POC trait/registry 文档，方便后续按插件式方式添加漏洞检测。
- 根据实际资产规模优化并发控制，例如按目标 IP 做令牌桶，进一步降低 WAF 触发风险。
