# watcher 实现进度记录


## 2026-08-16 MCP 资产查询分页

- 库存查询改为 offset/limit 分页, 返回 `items`/`total`/`has_more`/`next_offset`.
- 单次默认 50 条, 上限 200, 避免 `get_live_inventory`/`list_live_ports` 等接口一次拉整表.
- `get_system_context` 的嵌套列表同样分页, 不再按 1000 条整表导出.
- MCP 工具参数增加 `offset`; 有 `has_more` 时用 `next_offset` 继续翻页.


## 2026-08-16 MCP 资产库存活状态对接

- 新增只读 MCP 服务: `watcher mcp` 通过 stdio 向大模型暴露本地资产库存活状态.
- 工具面: `get_snapshot`/`get_live_inventory`/`get_system_context`, 以及系统、开放端口、Web 服务、存活 URL、告警、漏洞和批次查询.
- 资源: `watcher://snapshot`、`watcher://live/{ports,web,urls}`、`watcher://systems`、`watcher://system/{name}`.
- Prompt: `pentest_live_assets`、`review_web_exposure`, 仅基于已确认存活资产生成授权测试简报.
- MCP 不发起扫描或利用; stdout 保留给 JSON-RPC, 日志改写 stderr + SQLite.
- 新增 `src/mcp/` 与 `db` 库存查询; `cargo test --all-targets` 与 `cargo test --doc` 覆盖库存过滤、工具目录和 CLI 解析.


## 2026-08-16 CLI 动作优先重构

- 资产、字典、日志、业务系统从「名词 + 动作」改为「动作 + `--type` 名词筛选」.
- 新命令: `add`/`import`/`export`/`query`/`delete`/`unmark`/`rename`/`clear`, `query` 别名 `list`.
- 基准资产用 `--baseline`; Excel 导入为 `import --type excel`.
- `daemon` 与 `task` 保持生命周期子命令, 便于日常启停和批次操作.
- 旧命令 `url/port/ip/name/system/baseline/log/dict path` 不再保留兼容别名.
- `src/cli` 拆为 `args`/`actions`/`assets`/`handlers`, 单文件不超过 600 行.

## 2026-08-16 Release 原生三端构建

- 重构 `.github/workflows/release.yml`: 不再在 Ubuntu 上交叉编译, 改为各平台原生 runner.
- Linux: `ubuntu-latest` + `x86_64-unknown-linux-musl`.
- Windows: `windows-latest` + 原生 `x86_64-pc-windows-msvc`, 不再使用 `x86_64-pc-windows-gnu`.
- macOS: `macos-latest` + `aarch64-apple-darwin` (仅 Apple Silicon, 不支持 Intel).
- 发布模板同步更新产物列表.



## 2026-08-16 源码模块化重构

- 按功能拆分超大模块: `db`、`cli`、`config`、`report`、`dashboard`、`monitor::vuln`, 每个源文件不超过 600 行.
- 公开 API 路径保持不变, 包括 `watcher::{cli,config,daemon,dashboard,db,dict,import,local_time,logging,models,monitor,notify,report}`.
- 公开函数测试迁到 `tests/`; 私有/`pub(crate)` 函数测试留在对应源文件.
- 全部源码函数补齐 rustdoc 签名: 参数、返回值、Errors/Panics、调用示例.
- `cargo test --all-targets` 59 项通过; `cargo test --doc` 161 项通过; `cargo clippy --all-targets -- -D warnings` 通过.


## 2026-08-16 大规模全端口扫描数据库结构优化

- 端口扫描改为按 IP 一次事务落库，`ports` 只保留基准端口和当前开放端口，未知关闭端口不再写入。
- 端口变化告警按 IP 聚合，`details` 保存变化端口列表；新增 `scan_summaries` 替代端口级扫描日志。
- 迁移会清理历史关闭的非基准端口行；未完成扫描不会把未探测端口误标为关闭。
- 深度指纹日志改为按进度间隔汇总，避免开放端口过多时把 `logs` 表打满。

## 2026-07-18 Dashboard 指标卡片重复标题修复

- 移除指标卡片正文中重复渲染的标题，`资产`、`暴露面`、`数据量`、`基准` 仅保留有色边框标题；指标数值仍使用对应的强调色显示。
- 新增终端缓冲区回归测试，确保单个指标标题只会渲染一次。

## 2026-07-18 发布构建脚本修复与重构

- 修复 `scripts/build_release.sh` 将 `scripts/` 误判为项目根目录的问题，Cargo 清单、锁文件和默认产物目录现在均正确定位到仓库根目录。
- 重构参数解析、目标去重、依赖检查和产物路径计算；新增 `host`/`native` 目标、`--dry-run` 预览模式，以及可配置的 `CARGO` 和 `CARGO_TARGET_DIR`。
- 保持默认构建 Linux musl 与 Windows GNU 产物，并在实际交叉构建前检查 Rust target、提示潜在的链接器缺失。

## 2026-07-18 非基准资产单条添加

- 为 `url`、`port`、`ip`、`name` 增加 `add` 子命令，可直接为指定业务系统写入单条非基准资产。
- 端口添加支持可选 `--ip`，域名添加支持可选 `--bind-ip`；CLI 会拒绝其他资产类型不适用的参数。
- 新增 CLI 解析、参数校验和四类资产实际写入的回归测试；测试总数提升至 54。

## 2026-07-18 Dashboard TUI 与任务阶段进度

本阶段新增 `watcher dashboard` 交互式终端仪表盘，并将调度器阶段状态持久化，使运维人员可在一个界面中查看当前资产、风险和任务执行情况。

- 新增 `ratatui`/`crossterm` TUI，支持 2 秒默认自动刷新和 `q`/`Esc` 退出；critical、high、medium、low 告警按不同颜色渲染。
- 展示业务系统、域名、IP、端口、开放端口、Web 服务、URL、基准资产和字典量等关键指标。
- 新增 `batch_stages` 表，调度器会记录 DNS、端口扫描、服务指纹、Web 枚举、漏洞检查、深度指纹、报告和邮件通知等阶段的运行状态、完成时间及失败详情。
- 仪表盘展示最新批次、阶段完成度、pending work 队列、告警等级、漏洞数及最近告警；无批次数据时会以空状态安全展示。
- 新增数据库聚合、阶段中断恢复、颜色映射与 TUI 渲染测试；测试总数提升至 51。

## 2026-07-18 监测 HTTP 链路重构与集成测试扩展

本阶段收敛了 Web 枚举、轻量漏洞扫描和服务指纹的 HTTP 运行时边界，避免不同阶段以不一致的并发度执行请求，并防止大响应体被无上限读入内存。

- 新增 `lib.rs` 作为可复用应用库，`main.rs` 仅保留 CLI 进程入口和命令分发；库 API 可由集成测试及未来服务封装直接使用。
- 新增 `monitor::http` 共享模块，以流式方式仅保留最多 256 KiB 响应前缀；目录枚举和 sourcemap POC 复用该实现。
- 新增 `AppConfig::http_concurrency()`，将三类 HTTP 监测阶段统一限制为 1 到 8 个并发请求。
- 修复带查询参数的 JavaScript URL 推导常规 sourcemap 地址时遗漏 `.js.map` 的问题，并显式移除查询参数。
- 增加本地 HTTP 集成测试：覆盖受限响应读取、目录枚举 URL 写回与伪 200 过滤，以及 sourcemap 命中后的漏洞和告警落库。
- 测试数量由 40 增至 47；`cargo fmt`、`cargo clippy --all-targets -- -D warnings`、`cargo test --all-targets` 均通过。

## 2026-06-04 本地逻辑巡检与恢复链路优化

本阶段重点检查了任务中断后的恢复路径和扫描热路径，修复 `pending_work` 回放只标记完成但不写回有效结果的问题，并降低重复正则编译开销。

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
- 任务 4 Web 目录枚举：对 Web 服务按 path 字典慢速枚举，过滤伪 200 响应，同时尝试 `ip:port` 和同业务系统下 `name:port` 访问，并尝试从 HTML/JS 中提取入口；pending 回放会重新请求目标 URL 并按评分写回 URL 资产。
- 任务 5 轻量漏洞扫描：实现首个 POC `webpack_sourcemap_disclosure`，检测 JS sourcemap 标记和可访问 `.map` 文件；pending 回放复用完整 POC 检查流程，确保补偿目标仍可写入漏洞和告警。
- WAF 缓解：配置化 `per_target_delay_ms`，目录枚举和漏洞扫描在请求间加入延时。
- 未完成任务补偿：增加 `pending_work` 表，目录枚举和漏洞扫描会优先处理上一批次遗留目标；回放目标保留业务系统上下文，重复目标会更新到最新批次和系统归属，回放时按单条领取以避免停止请求导致未处理目标卡在 `running` 状态。
- 扫描热路径优化：Web 入口提取和 sourcemap 标记识别使用 `LazyLock` 缓存静态正则，避免每次解析页面或 JS 时重复编译。
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

- `src/main.rs`: CLI 入口和子命令分发.
- `src/cli/`: 动作优先命令定义与处理, 拆为 `args`/`actions`/`assets`/`handlers`.
- `src/config/`: 配置模型、默认值与加载, 拆为 `types`/`defaults`/`load`.
- `src/daemon.rs`: 后台进程启动与 PID 生命周期.
- `src/dashboard/`: 终端仪表盘主循环与渲染.
- `src/db/`: SQLite 迁移和数据访问层, 按 schema/assets/import/scans/batches/lists/snapshot 等拆分.
- `src/mcp/`: 只读 MCP 服务, 暴露存活端口、Web 服务、URL 状态和发现结果.
- `src/import/`: Excel 资产导入.
- `src/logging.rs`: tracing 日志初始化和 SQLite 日志落库.
- `src/dict/`: path 字典管理.
- `src/models/`: 跨模块共享数据结构.
- `src/monitor/`: DNS、端口扫描、指纹、目录枚举、漏洞扫描、调度器; sourcemap POC 在 `vuln_sourcemap`.
- `src/report/`: 报表摘要、明细表与 zip 打包.
- `src/notify/`: 邮件通知.

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
- `pending_work` 保存批次被停止后需要优先补偿的目标，包含所属业务系统、任务类型、目标、优先级和状态；同一任务目标重复入队时会更新最新上下文并保留更高优先级。
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
- `cargo test` 通过，当前 39 个单元测试全部成功。
- 默认配置初始化逻辑保留，会创建 `~/.config/watcher/watcher.yml` 和 `~/.config/watcher/watcher.db`。
- `--example` 能输出示例配置且不会初始化数据库。
- `log query` 可查询 SQLite 中的日志记录。
- CLI help 输出正常。

## 后续建议

- 增加真实 Excel 文件的集成测试。
- 增加 HTTP mock 服务测试目录枚举、pending 回放和 sourcemap POC 的端到端行为。
- 增加 daemon 后台化方式，例如 systemd service 示例或 PID 文件管理。
- 增加更细粒度的任务状态表，展示每个任务阶段的进度。
- 增加报告中的差异对比章节，例如新增端口、关闭端口、新增 URL、DNS 变化、漏洞列表。
- 增加 POC trait/registry 文档，方便后续按插件式方式添加漏洞检测。
- 根据实际资产规模优化并发控制，例如按目标 IP 做令牌桶，进一步降低 WAF 触发风险。
