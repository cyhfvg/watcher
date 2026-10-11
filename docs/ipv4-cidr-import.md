# IPv4 CIDR 导入

`watcher import --type ip` 将文件中的 IPv4 地址和 CIDR 网段展开为逐个主机地址后写入 `ip_addresses`。扫描、端口绑定和域名 `bind_ip` 仍只接受单个 IPv4。

## 行为

- 每行一个 `a.b.c.d` 或 `a.b.c.d/prefix`。
- CIDR 按网络位掩码展开, 包含网络地址和广播地址。`10.0.0.1/24` 按 `10.0.0.0/24` 展开。
- 前缀 `/0` 到 `/32` 都接受。展开后的主机数量由调用方自行控制。
- 导入计数是展开后的主机数, 不是文件行数。
- IPv6 和非法文本仍拒绝。

## 命令

```bash
watcher import --type ip --system jsdx_iboc ./ips.txt
watcher import --type ip --baseline --system core ./baseline-nets.txt
watcher query --type ip --system jsdx_iboc --keyword 132.254.113
```

## MCP

- `expand_ipv4_cidr`: 按同样规则预览展开结果, 分页默认 50、上限 200, 不写库。
- `query_ips`: 查询已经导入的主机地址。CIDR 不会作为网段行保存。

相关实现: `src/ipv4.rs`, `Database::import_ips_for_system`.
