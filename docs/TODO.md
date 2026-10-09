# TODO

## 已完成（2026-10-09 扫描日志与写锁）

- 端口扫描不再为不可达 IP 写逐条日志或空扫描摘要；SQLite 只留 info 及以上。
- `record_ip_scan` 使用 IMMEDIATE 事务和 30s busy_timeout，并发写不再因 `database is locked` 丢结果。
- DNS、指纹、URL upsert、pending 等高并发写库同样改为 IMMEDIATE。
- DNS/Web 枚举/指纹/漏洞的逐目标失败 WARN 改为首条采样 + 结束计数。



## 已完成（2026-09-29 重构收尾）

- 明确 Web 特征才标 is_web; 按 host 限速; nmap 按 IP 聚合; 漏洞溢出入 pending.
- 回放不重复请求; 伪 200 抑制; 同源 .js 过滤与停止 flush; 负样本大小写与最小长度.
- 报表/SMTP 带超时; 模块拆分后源文件均小于 600 行.

## 已完成（2026-09-29 端口关闭判定）

- 端口扫描只把确认过的 connection refused 记为关闭. 超时和不可达不再删除历史开放端口.

## 已完成（2026-09-29 批次停止收尾）

- 超时和关机信号走同一条收尾: 停止标志, 等待在途阶段, 回队 running pending, 批次标 interrupted.

## 已完成（2026-09-29 pending 回放）

- 回放传输失败保持 pending, 最多重试 3 次后放弃.

## 已完成（2026-09-29 IPv4）

- 入口拒绝非 IPv4. 已入库的 IPv6 跳过探测.

## 已完成（2026-09-29 停止与 fd 上限）

- 停止请求会跳过后续阶段, 未完成 IP 不标扫描完成.
- 端口扫描并发按 fd 预算限制在途连接.






## 已完成（2026-09-29 Web 枚举并发）

- Web 枚举使用独立的 `web.concurrency`，按 URL 请求限流，默认 64，上限 512。
- 未实现按目标 IP 的令牌桶。单主机保护仍靠降低 `web.concurrency` 或提高 `probe.per_target_delay_ms`。


## 已完成（2026-08-16 MCP 使用例子）

- 编写 `docs/mcp.example.md`, 用自然语言说明如何让大模型通过 MCP 查询存活资产并做授权测试规划.


## 已完成（2026-08-16 MCP 分页）

- `get_live_inventory`/`list_live_ports` 等资产接口改为分页返回, 默认 50、上限 200.
- 响应带 `total`/`has_more`/`next_offset`, 避免大模型一次取出整张资产表.

## 已完成（2026-08-16 MCP 资产库）

- 增加 `watcher mcp` stdio 服务, 只读暴露存活端口、Web 服务、URL 状态、告警和漏洞.
- 大模型可通过 MCP tools/resources/prompts 读取已确认存活资产, 再自行规划授权测试.



## 已完成（2026-08-16 CLI 动作优先重构）

- 命令面改为动作子命令 + `--type` 名词筛选, daemon/task 保持生命周期子命令.
- 旧名词优先命令不再保留兼容别名; README 与报表说明已同步.

## 已完成（2026-08-16 Release 原生构建）

- Release workflow 改为 Linux/Windows/macOS 原生编译, 不再交叉编译.

## 已完成（2026-08-16 源码重构）

- 按功能拆分全部源码模块, 单文件不超过 600 行.
- 公开函数测试迁到 `tests/`, 私有函数测试留在对应源文件.
- 全部源码函数补齐签名文档.

## 已完成（2026-08-16）

- 大规模全端口扫描数据库优化：按 IP 聚合落库、聚合告警、`scan_summaries` 摘要表。

## 已完成（2026-07-18）

- Dashboard 指标卡片标题去重：标题由卡片边框统一渲染，避免与正文重复显示。

## 测试覆盖

- 增加真实 Excel 文件导入测试，验证多端口、空字段、重复资产和基准标记。
- 补充 pending work 回放的 HTTP mock 集成测试，覆盖停止、领取、重试和完成状态迁移。

## 运行与恢复

- 增加 pending work 状态巡检命令，便于查询 `pending/running/done` 目标和手动重置异常任务。
- 补充 daemon 部署示例，例如 systemd service、PID 文件或健康检查脚本。

## 扫描能力

- 设计 POC trait/registry 文档，方便后续按插件式方式增加漏洞检测。
- 根据真实资产规模优化并发控制，例如按目标 IP 或系统做令牌桶，进一步降低 WAF 触发风险。
- 增加更多目录枚举负样本识别规则，减少统一错误页、登录跳转页和网关占位页误报。

## 报表与可视化

- 增强报告差异章节，独立展示新增端口、关闭端口、新增 URL、DNS 变化和漏洞列表。
- 为 `details.xlsx` 增加列宽、冻结表头和筛选等可读性优化。
- 增加报告样例文件，便于发布包和 README 引用。
