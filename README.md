# watcher

Long-running asset monitoring toolkit for DNS records, TCP ports, web services,
web paths, URL status, and lightweight exposure checks.

> 中文文档: [README.zh-CN.md](README.zh-CN.md)
>
> This PROJECT was written with assistance from Codex AI.

## Overview

`watcher` is a conservative security operations CLI for keeping a baseline of
business-facing assets and detecting changes over time. It stores imported and
discovered assets in a local SQLite database, runs scheduled monitoring batches,
generates human-readable reports, and can send the report package by email.

It is designed for teams that need to answer questions like:

- Did any domain start resolving to a different IP?
- Did a new TCP port open on a known asset?
- Which open ports look like web services?
- Did directory enumeration discover non-baseline URLs?
- Did a lightweight POC find an exposed sourcemap?
- What changed since the imported asset baseline?

`watcher` favors slow, low-noise probing over aggressive scanning. Use it only on
assets that you own or are authorized to assess.

## Features

- **Baseline asset inventory**: import domains, real IPs, bound IPs, ports, and
  URLs from Excel, or manage individual baseline assets from the CLI.
- **Business-system centric model**: assets are grouped by system so reports
  remain useful for ownership and remediation.
- **DNS monitoring**: resolves configured domain names and records DNS change
  alerts.
- **Slow TCP port monitoring**: scans configured ports with per-IP and per-port
  concurrency controls.
- **Service fingerprinting**: identifies HTTP/HTTPS services and captures simple
  banner/fingerprint details.
- **Web path enumeration**: uses a path dictionary, filters common fake-200
  responses, and can discover links from HTML and JavaScript.
- **Lightweight vulnerability checks**: currently includes
  `webpack_sourcemap_disclosure`.
- **SQLite persistence**: local, portable storage with built-in migrations.
- **Reports**: always generates `summary.md`, plus detail files in `xlsx`,
  `json`, or `csv`, then packages everything as a zip.
- **SMTP notification**: sends batch summaries and report zip attachments when
  enabled.
- **Static-build friendly dependencies**: uses `rustls` for HTTP/SMTP TLS and
  bundled SQLite through `rusqlite`.

## Status

The project is currently an early `0.1.0` implementation. The core workflow is
usable, but command output, report structure, and POC coverage may still evolve.

## Installation

### Requirements

- Rust toolchain with Cargo
- A platform supported by `tokio`, `rusqlite`, and `reqwest`

### Build from source

```bash
git clone <repository-url>
cd watcher
cargo build --release
```

The binary will be available at:

```bash
target/release/watcher
```

For local development, you can also run commands through Cargo:

```bash
cargo run -- --help
```

## Quick Start

Create the default config and database:

```bash
watcher init
```

Print an example YAML config:

```bash
watcher --example
```

Import baseline assets from Excel:

```bash
watcher baseline import --asset-type excel ./assets.xlsx
```

Import a web path dictionary:

```bash
watcher dict path import ./paths.txt
```

Run one monitoring batch:

```bash
watcher task run --once
```

Query recent logs:

```bash
watcher log query --limit 50
```

Build a report package for the latest batch:

```bash
watcher report
```

## Default Paths

`watcher` uses the user config directory by default:

- Config: `~/.config/watcher/watcher.yml`
- Database: `~/.config/watcher/watcher.db`
- Reports: `~/.config/watcher/reports`
- Daemon PID file: next to the config file as `watcher.pid`

Running `watcher init` or any normal command creates missing config/database
paths automatically.

## Asset Model

The database is organized around business systems:

- `systems`: business systems and ownership boundaries.
- `domains`: domain names and their expected/latest resolved IPs.
- `ip_addresses`: real IP addresses and resolved IP addresses.
- `ports`: TCP port state, service protocol, web flag, and fingerprint.
- `urls`: imported URLs, enumerated URLs, JS-discovered URLs, and vuln URLs.
- `dict_paths`: web enumeration dictionary entries.
- `batches`: monitoring batch status and report package path.
- `alerts`: DNS, port, and vulnerability events.
- `vulnerabilities`: lightweight POC findings.
- `pending_work`: carry-over work when a batch stops before completion.
- `logs`: application logs stored in SQLite for CLI query/export.

`domains`, `ip_addresses`, `ports`, and `urls` include an `is_baseline` marker.
Imported assets are baseline assets; assets found by scanning, enumeration, or
POCs are non-baseline discoveries by default.

## Excel Import

The first worksheet should contain these headers:

```text
id,system,servername,real_ip,servername_bind_ip,port,url
```

Column behavior:

- `id`: ignored.
- `system`: business system name. Required.
- `servername`: domain name. Optional.
- `real_ip`: real asset IP address.
- `servername_bind_ip`: expected or previously known domain binding IP.
- `port`: TCP ports. Supports separators such as `80,443/8080`.
- `url`: related URL. Optional.

Example:

```bash
watcher baseline import --asset-type excel ./assets.xlsx
```

## Baseline Management

Baseline assets can also be managed without Excel:

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

`baseline delete` removes the asset row. `baseline unmark` keeps the row but
changes it from baseline to non-baseline.

## Business Systems

```bash
watcher system add core
watcher system query --keyword core
watcher system export ./systems.csv
watcher system rename core core-prod
watcher system delete core-prod
```

`system query` and `system export` include domain, IP, port, URL, and baseline
counters. Deleting a system cascades to assets under that system.

## Monitoring Pipeline

Each batch runs the following stages:

1. **DNS resolution**: resolves every domain and records DNS changes.
2. **Port scanning**: probes configured TCP ports on real IP assets and records
   open/closed changes.
3. **Fingerprinting**: checks open ports for HTTP/HTTPS and banner details.
4. **Web enumeration**: tries dictionary paths against web services, including
   `ip:port` and same-system `name:port` forms, then extracts possible links
   from HTML/JS.
5. **Lightweight POCs**: runs exposure checks in parallel with web enumeration.
6. **Report packaging**: writes `summary.md` and detail files, then creates a
   zip package.
7. **Email notification**: sends the summary and zip attachment when enabled.

## Configuration

Use `watcher --example` to print the default YAML config, or see
[examples/watcher.yml](examples/watcher.yml).

### Probe Settings

Port scanning uses two concurrency controls:

```yaml
probe:
  connect_timeout_ms: 2000
  scan_ip_concurrency: 4
  scan_port_concurrency_per_ip: 4
```

Effective port probe parallelism is:

```text
scan_ip_concurrency * scan_port_concurrency_per_ip
```

`probe.concurrency` is still used by non-port tasks such as fingerprinting, web
enumeration, and vulnerability checks.

Configure explicit ports:

```yaml
probe:
  scan_ports:
    - 80
    - 443
    - 8080
```

Or scan all TCP ports:

```yaml
probe:
  scan_ports: full
```

`full` and `all` both expand to `1..=65535`. Full-port scans can take a long
time; use longer scheduler intervals and lower concurrency for conservative
monitoring.

### DNS Servers

An empty `dns_servers` list uses the host/system resolver:

```yaml
probe:
  dns_servers: []
```

Custom DNS servers support `IP` and `IP:port` forms:

```yaml
probe:
  dns_servers:
    - 8.8.8.8
    - 1.1.1.1:53
```

### Reports

`summary.md` is always generated. Details are controlled by `report.format`:

```yaml
report:
  output_dir: ~/.config/watcher/reports
  format: xlsx
```

Supported formats:

- `xlsx`: one `details.xlsx` workbook with `alerts`, `vulnerabilities`, `urls`,
  and `open_ports` sheets.
- `json`: one structured `details.json` file.
- `csv`: separate detail CSV files.

## Daemon and Tasks

Run continuously in the background:

```bash
watcher daemon run
```

Run in the foreground for debugging:

```bash
watcher daemon run --foreground
```

Manage daemon state:

```bash
watcher daemon status
watcher daemon stop
watcher daemon restart
```

Manage task batches:

```bash
watcher task run --once
watcher task list
watcher task status
watcher task stop
```

## Logs

Runtime logs are stored in SQLite and can be queried or exported:

```bash
watcher log query --level info --limit 100
watcher log query --level error --keyword smtp --limit 20
watcher log export ./watcher-logs.csv --limit 1000
watcher log clear --before 2026-05-15T00:00:00Z
```

## Email Notification

SMTP notifications are optional. QQ/Foxmail users should use an SMTP
authorization code instead of the web login password.

`smtp_security: auto` maps port `465` to implicit TLS/SMTPS and port `587` to
STARTTLS:

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

For mail troubleshooting:

```bash
watcher log query --keyword email --level warn --limit 20
watcher log query --keyword smtp --limit 20
```

## Command Reference

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
watcher url import --system <system> <file>
watcher port import --system <system> [--ip <ip>] <file>
watcher ip import --system <system> <file>
watcher name import --system <system> [--bind-ip <ip>] <file>
watcher url|port|ip|name export|query|delete
watcher report
```

Use `watcher <command> --help` for exact arguments.

## Development

Run checks:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

Run the CLI locally:

```bash
cargo run -- --help
cargo run -- --example
cargo run -- task run --once
```

## Roadmap

- Broader POC registry and clearer extension points.
- Integration tests with mock HTTP services and sample Excel files.
- Systemd service examples for daemon deployment.
- More granular per-stage task progress.
- Richer report comparison sections for newly discovered assets.

## License

MIT. See [LICENSE](LICENSE).
