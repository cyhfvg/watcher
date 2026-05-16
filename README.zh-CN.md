# watcher

长期运行的资产监控命令行工具，用于跟踪 DNS 解析、TCP 端口、Web 服务、Web
路径、URL 状态和轻量级暴露风险。

> 主文档为英文版: [README.md](README.md)
>
> 本 项目 使用 Codex AI 工具辅助编写。

## 简介

`watcher` 面向安全运营和资产治理场景。它可以维护一份业务系统资产基线，周期性
执行监控批次，将导入资产和发现资产保存到本地 SQLite 数据库，并生成报表包；启用
邮件配置后，还可以把监控摘要和 zip 附件发送给指定收件人。

它主要帮助回答这些问题：

- 域名解析是否发生变化？
- 已知资产上是否出现新的开放 TCP 端口？
- 哪些开放端口疑似 Web 服务？
- Web 目录枚举是否发现非基线 URL？
- 轻量 POC 是否发现 sourcemap 暴露？
- 当前发现资产和导入基线相比有什么差异？

`watcher` 的探测策略偏慢速和保守，优先降低噪声和误触发风险。请只在你拥有或被
授权评估的资产范围内使用。

## 功能特性

- **基线资产管理**：从 Excel 导入域名、实际 IP、绑定 IP、端口和 URL，也支持用
  CLI 精确维护单个基线资产。
- **按业务系统组织资产**：资产以业务系统为聚合根，便于定位归属和推动整改。
- **DNS 监控**：解析域名并记录 DNS 变化告警。
- **慢速端口监控**：按配置扫描 TCP 端口，支持 IP 级和单 IP 端口级并发控制。
- **服务指纹识别**：识别 HTTP/HTTPS 服务并记录基础 banner/指纹。
- **Web 目录枚举**：使用 path 字典枚举，过滤常见伪 200 响应，并从 HTML/JS 中提取
  可能入口。
- **轻量漏洞检查**：当前内置 `webpack_sourcemap_disclosure`。
- **SQLite 持久化**：本地文件数据库，内置迁移。
- **报表打包**：始终生成 `summary.md`，并按配置输出 `xlsx`、`json` 或 `csv` 明细，
  最后打包为 zip。
- **SMTP 邮件通知**：按配置发送摘要和报告附件。
- **便于静态化构建**：HTTP/SMTP TLS 使用 `rustls`，SQLite 使用 `rusqlite` bundled
  模式，避免 OpenSSL 依赖。

## 当前状态

项目当前处于早期 `0.1.0` 阶段。核心工作流已经可用，但命令输出、报表结构和 POC
覆盖范围后续仍可能调整。

## 安装

### 环境要求

- Rust 工具链和 Cargo
- `tokio`、`rusqlite`、`reqwest` 支持的平台

### 从源码构建

```bash
git clone <repository-url>
cd watcher
cargo build --release
```

构建后的二进制文件位于：

```bash
target/release/watcher
```

开发时也可以直接通过 Cargo 运行：

```bash
cargo run -- --help
```

## 快速开始

创建默认配置和数据库：

```bash
watcher init
```

输出示例 YAML 配置：

```bash
watcher --example
```

从 Excel 导入基线资产：

```bash
watcher baseline import --asset-type excel ./assets.xlsx
```

导入 Web path 字典：

```bash
watcher dict path import ./paths.txt
```

执行一次监控批次：

```bash
watcher task run --once
```

查询最近日志：

```bash
watcher log query --limit 50
```

为最新批次生成报告包：

```bash
watcher report
```

## 默认路径

`watcher` 默认使用用户配置目录：

- 配置文件：`~/.config/watcher/watcher.yml`
- 数据库：`~/.config/watcher/watcher.db`
- 报表目录：`~/.config/watcher/reports`
- Daemon PID 文件：配置文件同目录下的 `watcher.pid`

运行 `watcher init` 或任意普通命令时，会自动创建缺失的配置和数据库路径。

## 资产模型

数据库以业务系统为核心：

- `systems`：业务系统和资产归属边界。
- `domains`：域名、期望解析 IP 和最新解析 IP。
- `ip_addresses`：实际 IP 和解析得到的 IP。
- `ports`：TCP 端口状态、服务协议、Web 标记和指纹。
- `urls`：导入 URL、枚举发现 URL、JS 发现 URL 和漏洞关联 URL。
- `dict_paths`：Web 目录枚举字典。
- `batches`：监控批次状态和报告路径。
- `alerts`：DNS、端口和漏洞事件。
- `vulnerabilities`：轻量 POC 命中结果。
- `pending_work`：批次停止后待补偿的任务。
- `logs`：应用运行日志，可通过 CLI 查询和导出。

`domains`、`ip_addresses`、`ports`、`urls` 都包含 `is_baseline` 标记。导入资产为
基线资产；扫描、枚举和 POC 产生的新资产默认是非基线发现资产。

## Excel 导入

第一张工作表应包含以下表头：

```text
id,system,servername,real_ip,servername_bind_ip,port,url
```

字段说明：

- `id`：忽略，不导入。
- `system`：业务系统名称，必填。
- `servername`：域名，可为空。
- `real_ip`：真实资产 IP。
- `servername_bind_ip`：域名期望或历史绑定 IP。
- `port`：TCP 端口，支持 `80,443/8080` 这类分隔写法。
- `url`：相关 URL，可为空。

导入命令：

```bash
watcher baseline import --asset-type excel ./assets.xlsx
```

## 基线资产管理

也可以不通过 Excel，直接维护基线资产：

```bash
watcher baseline add --asset-type url --system core https://example.com/login
watcher baseline import --asset-type url --system core ./urls.txt
watcher baseline query --asset-type ip --keyword 10.0.0

watcher baseline add --asset-type ip --system core 10.0.0.1
watcher baseline add --asset-type port --system core --ip 10.0.0.1 443
watcher baseline import --asset-type port --system core --ip 10.0.0.1 ./ports.txt
watcher baseline add --asset-type name --system core --bind-ip 10.0.0.1 example.com

watcher baseline unmark --asset-type port --system core --ip 10.0.0.1 8443
watcher baseline delete --asset-type url --system core https://example.com/old
```

`baseline delete` 会删除资产行；`baseline unmark` 只取消基线标记并保留资产行。

## 业务系统

```bash
watcher system add core
watcher system query --keyword core
watcher system export ./systems.csv
watcher system rename core core-prod
watcher system delete core-prod
```

`system query` 和 `system export` 会输出域名、IP、端口、URL 以及基线数量。删除业务
系统会级联删除该系统下的资产。

## 监控链路

每个批次按以下阶段执行：

1. **DNS 解析**：解析所有域名并记录 DNS 变化。
2. **端口扫描**：对实际 IP 探测配置的 TCP 端口，记录开放/关闭变化。
3. **指纹识别**：识别开放端口上的 HTTP/HTTPS 和基础 banner。
4. **Web 目录枚举**：对 Web 服务尝试 path 字典，同时尝试 `ip:port` 和同业务系统
   下的 `name:port` 访问，并从 HTML/JS 中提取可能入口。
5. **轻量 POC**：与 Web 枚举并行执行暴露风险检查。
6. **报表打包**：生成 `summary.md` 和明细文件，并创建 zip 报告包。
7. **邮件通知**：启用后发送摘要和 zip 附件。

## 配置

使用 `watcher --example` 输出默认 YAML，也可以参考
[examples/watcher.yml](examples/watcher.yml)。

### 探测配置

端口扫描使用两层并发控制：

```yaml
probe:
  connect_timeout_ms: 2000
  scan_ip_concurrency: 4
  scan_port_concurrency_per_ip: 4
```

端口探测实际并发为：

```text
scan_ip_concurrency * scan_port_concurrency_per_ip
```

`probe.concurrency` 仍用于指纹识别、Web 枚举、漏洞检查等非端口任务。

显式配置端口：

```yaml
probe:
  scan_ports:
    - 80
    - 443
    - 8080
```

全端口扫描：

```yaml
probe:
  scan_ports: full
```

`full` 和 `all` 等价，都会展开为 `1..=65535`。全端口扫描耗时较长，建议配合更长的
调度周期和更低并发。

### DNS 服务器

空 `dns_servers` 表示使用主机/系统解析器：

```yaml
probe:
  dns_servers: []
```

自定义 DNS 支持 `IP` 或 `IP:port`：

```yaml
probe:
  dns_servers:
    - 8.8.8.8
    - 1.1.1.1:53
```

### 报表

`summary.md` 始终生成。明细格式由 `report.format` 控制：

```yaml
report:
  output_dir: ~/.config/watcher/reports
  format: xlsx
```

支持格式：

- `xlsx`：生成一个 `details.xlsx`，包含 `alerts`、`vulnerabilities`、`urls`、
  `open_ports` 工作表。
- `json`：生成结构化 `details.json`。
- `csv`：生成多份明细 CSV。

## Daemon 和任务

后台持续运行：

```bash
watcher daemon run
```

前台调试：

```bash
watcher daemon run --foreground
```

管理 daemon：

```bash
watcher daemon status
watcher daemon stop
watcher daemon restart
```

管理监控批次：

```bash
watcher task run --once
watcher task list
watcher task status
watcher task stop
```

## 日志

运行日志会存入 SQLite，可查询、导出或清理：

```bash
watcher log query --level info --limit 100
watcher log query --level error --keyword smtp --limit 20
watcher log export ./watcher-logs.csv --limit 1000
watcher log clear --before 2026-05-15T00:00:00Z
```

## 邮件通知

SMTP 通知是可选能力。QQ/Foxmail 建议使用 SMTP 授权码，不要使用网页登录密码。

`smtp_security: auto` 会将 `465` 映射为隐式 TLS/SMTPS，将 `587` 映射为 STARTTLS：

```yaml
email:
  enabled: true
  smtp_host: smtp.qq.com
  smtp_port: 465
  smtp_security: auto
  username: your-account@qq.com
  password: "your-smtp-authorization-code"
  from: your-account@qq.com
  to:
    - security@example.com
```

邮件排障命令：

```bash
watcher log query --keyword email --level warn --limit 20
watcher log query --keyword smtp --limit 20
```

## 命令速查

```bash
watcher init
watcher --example

watcher baseline import --asset-type excel <file>
watcher baseline add --asset-type url|port|ip|name --system <system> <value>
watcher baseline import --asset-type url|port|ip|name --system <system> <file>
watcher baseline query --asset-type url|port|ip|name
watcher baseline export --asset-type url|port|ip|name <file>
watcher baseline delete|unmark --asset-type url|port|ip|name --system <system> <value>

watcher system add|query|export|delete|rename
watcher daemon run|status|stop|restart
watcher task run|list|status|stop
watcher log query|export|clear
watcher dict path import|export|query|delete
watcher url export|query|delete
watcher port export|query|delete
watcher ip export|query|delete
watcher name export|query|delete
watcher report
```

使用 `watcher <command> --help` 查看准确参数。

## 开发

运行检查：

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

本地运行 CLI：

```bash
cargo run -- --help
cargo run -- --example
cargo run -- task run --once
```

## 路线图

- 扩展 POC registry，并提供更清晰的扩展点。
- 增加 mock HTTP 服务和示例 Excel 的集成测试。
- 增加 systemd service 示例，方便部署 daemon。
- 提供更细粒度的任务阶段进度。
- 增强报表中的新增资产差异对比。

## 许可证

MIT。详见 [LICENSE](LICENSE)。
