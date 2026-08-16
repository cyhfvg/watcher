# watcher MCP 自然语言使用例子

本文给已经把 `watcher mcp` 接到大模型 Host 的人用。重点不是 CLI 参数，而是你可以直接对模型说的话，以及模型应当调用的 watcher 工具。

watcher 只提供资产库存。它不扫描、不探测、不利用。模型只能读取 watcher 已经确认的存活端口、Web 服务、URL 状态、告警和漏洞，再据此做**授权范围内**的测试规划。

## 启用

先让本地库存有数据：

```bash
watcher init
watcher import --type excel ./assets.xlsx
watcher task run --once
```

再启动 MCP：

```bash
watcher mcp
```

Host 配置示例（Claude Desktop / Cursor）：

```json
{
  "mcpServers": {
    "watcher": {
      "command": "watcher",
      "args": ["mcp"]
    }
  }
}
```

`command` 必须是 Host 能执行到的路径。开发态可以用 `cargo run -- mcp` 对应的绝对路径。

stdio 专用于 JSON-RPC。日志写到 stderr 和 SQLite。这是前台进程。

## 使用约定

对模型说话时尽量带上下面这些约束，避免它发明目标或一次拉整表：

- 只使用 watcher 返回的存活资产。
- 列表分页：默认 50 条，单次最多 200 条。看到 `has_more: true` 时用 `next_offset` 继续，不要靠加大 `limit`。
- 先看快照和业务系统，再下钻某个系统。
- 未授权的主机、端口、URL 一律跳过。
- 不要让模型编写 exploit 或对库存外目标出手。

资产列表的返回形状：

```json
{
  "items": [],
  "total": 312,
  "offset": 0,
  "limit": 50,
  "has_more": true,
  "next_offset": 50
}
```

`get_live_inventory` 和 `get_system_context` 里的嵌套列表也是这个形状。

## 工具速查

| 你想知道什么 | 对模型说的方向 | 应调用的工具 |
| --- | --- | --- |
| 现在监控得怎么样 | 看总览、批次、告警 | `get_snapshot`，必要时 `list_batches` |
| 有哪些业务系统 | 列出系统及资产量 | `list_systems` |
| 哪些东西现在是活的 | 看开放端口 / Web / 2xx URL | `get_live_inventory` |
| 某一个系统怎么测 | 按系统名下钻 | `get_system_context` |
| 继续翻某一类资产 | 指定 system / keyword / offset | `list_live_ports`、`list_web_services`、`list_live_urls` |
| 域名、IP、全部 URL | 查库存，不一定存活 | `query_names`、`query_ips`、`query_urls` |
| 这轮监控发现了什么 | 看告警和漏洞 | `list_alerts`、`list_vulnerabilities` |
| 直接生成测试简报 | 使用内置 prompt | `pentest_live_assets`、`review_web_exposure` |

## 例子 1：第一次接通，先摸清库存

你可以对模型说：

> 先不要做任何测试。用 watcher 看当前资产监控总览：有多少业务系统、开放端口、Web 服务、URL，最近一次批次是否完成，有没有高危告警。用中文简要汇报，不要编造数字。

期望调用：

1. `get_snapshot`
2. 若批次状态不清楚，再 `list_batches`，`limit` 用 5 即可

模型应汇报 snapshot 里的计数和最近告警，而不是开始列几百个端口。

补充一句，让它按系统拆开：

> 列出 watcher 里的业务系统，按开放端口和 URL 数量从高到低说前几个。只报库存里有的系统名。

期望调用：`list_systems`。

## 例子 2：只要已经确认存活的资产

> 从 watcher 取出当前确认存活的资产：开放 TCP 端口、已识别的 HTTP/HTTPS 服务、最近探测为 2xx/3xx 的 URL。先给我第一页。如果 has_more 为 true，先告诉我还有多少，等我同意再翻页。不要把未探测或 404 的 URL 当成活资产。

期望调用：`get_live_inventory`，不传或只传很小的 `limit`。

如果第一页 `live_ports.has_more` 为 true，你可以接着说：

> 继续拉开放端口的下一页，offset 用刚才返回的 next_offset。其他列表先别动。

期望调用：`list_live_ports`，`offset` 等于上一页的 `next_offset`。

反例（不要这样说，模型容易一次灌表）：

> 把所有存活端口和 URL 全部导出，limit 调到最大。

正确说法是「一页一页来」。单次 `limit` 会被封顶到 200，仍然可能很长。

## 例子 3：只看某一个业务系统

把 `core` 换成你的真实系统名。系统名必须和 watcher 里完全一致。

> 只看业务系统 core。给我这个系统当前的域名、IP、存活端口、Web 服务、存活 URL，以及最新批次的告警和漏洞。先第一页。然后基于这些活资产，列一份授权测试提纲：先信息收集，再配置/暴露面复查。不要写 exploit，不要发明库存里没有的主机或 URL。

期望调用：`get_system_context`，`system=core`。

如果模型说系统不存在，先让它查名字：

> core 可能名字不完全一致。先在 watcher 里按关键字 core 查业务系统，把准确系统名报给我，未经确认不要继续。

期望调用：`list_systems`，`keyword=core`。

确认名字后再说：

> 准确系统名是 core-prod。对 core-prod 做 get_system_context，然后只针对返回的存活 URL 和 Web 服务做暴露面复盘。

## 例子 4：Web 暴露面复查

> 复查 watcher 里已经识别出的 Web 资产。先看开放的 HTTP/HTTPS 端口和指纹，再看状态为 2xx/3xx 的 URL。重点找：非基线 URL、意外开放的管理端口、指纹异常、已经记下来的漏洞。按业务系统分组。不要对库存外的域名做建议。

期望调用顺序：

1. `list_web_services`
2. `list_live_urls`
3. 若需要对照全部 URL（含 404 / 未探测），再 `query_urls`
4. `list_vulnerabilities`

也可以直接用内置 prompt：

> 使用 watcher 的 review_web_exposure prompt，系统限定为 core。根据返回的简报做中文复盘，列出优先处理的 5 个点。

期望调用：prompt `review_web_exposure`，`system=core`。

## 例子 5：授权渗透测试规划

先声明授权范围，再要规划：

> 我已被授权评估业务系统 core 的已监控资产，范围仅限 watcher 标记为存活的端口和 URL。请使用 pentest_live_assets，系统填 core。输出一份分阶段计划：侦察、Web 入口梳理、已知漏洞复查、需要人工确认的点。禁止提供 exploit 代码。如果某一页 has_more 为 true，先说明未读完，不要假装已经看完全部资产。

期望调用：prompt `pentest_live_assets`，`system=core`。

若要覆盖全部系统，而不是某一个：

> 使用 pentest_live_assets，不要限定系统。只根据第一页存活资产做总计划。若总数很大，按业务系统拆成后续任务，而不是要求我一次看完全库。

期望调用：prompt `pentest_live_assets`，不传 `system`。

模型若开始编造 `https://admin.example.net/debug` 这类库存没有的地址，应打断：

> 刚才那个 URL 不在 watcher 库存里。删掉所有未出现在 get_system_context 或 list_live_urls 返回值中的目标，只保留库存里的。

## 例子 6：按关键字缩小面

端口 / 指纹：

> 在 watcher 存活端口里搜 nginx 或 8080，告诉我属于哪些系统、是否被标成 Web。

期望调用：`list_live_ports` 或 `list_web_services`，`keyword=nginx` 或 `keyword=8080`。

URL：

> 只看存活 URL 里带 /admin、/login、/actuator、/swagger 的路径。按系统列出。不要自己补全路径。

期望调用：多次 `list_live_urls`，分别用这些关键字；或先 `list_live_urls` 再在返回的 `items` 里筛选。

IP / 域名：

> 查 10.0.0 网段在 watcher 里登记过的 IP，以及绑定到这些 IP 的域名。分辨 imported、manual、resolved。

期望调用：`query_ips`，`keyword=10.0.0`；再 `query_names`，用对应 IP 或系统名。

## 例子 7：看监控发现，而不是再扫一遍

> 不要重新扫描。看 watcher 最新批次的告警和漏洞：DNS 变化、端口开关、sourcemap 一类 POC。按严重级别分组，并标出对应业务系统。如果告警很多，先第一页。

期望调用：

1. `list_batches`，确认最新批次
2. `list_alerts`（可带 `batch`，不带则用最新批次）
3. `list_vulnerabilities`

只看某一个系统：

> 只要 core 在最新批次里的 high/critical 告警和漏洞。

期望调用：`list_alerts` / `list_vulnerabilities`，`system=core`，必要时 `keyword=high`。

## 例子 8：分页翻完一类资产

适合资产量已经明显超过 50 的库。

> 把业务系统 core 的存活 URL 全部翻完，但每次只要一页，limit=50。每翻一页先摘要：新增了哪些非基线 URL、状态码分布。直到 has_more 为 false。不要把 limit 调到 200 来少翻几次，除非我明确同意。

期望调用：循环 `list_live_urls`：

- 第 1 次：`system=core`，`limit=50`，`offset=0`
- 第 2 次：`offset` 用上一页 `next_offset`
- 直到 `has_more=false`

同样的句式可以换成端口：

> 用同样方式翻完 core 的开放端口。每页只关心非 Web 的高端口和未识别指纹。

期望调用：`list_live_ports`，`system=core`，按 `next_offset` 前进。

## 例子 9：对比基线与发现资产

watcher 用 `is_baseline` 区分导入基线和扫描发现。

> 在 core 的存活 URL 和开放端口里，把基线资产和后来发现的资产分开。发现资产里哪些现在是活的？哪些 Web 服务不在基线里？不要建议删除基线，只标出需要人工确认的新增暴露面。

期望调用：`get_system_context` 或 `list_live_urls` + `list_live_ports` + `list_web_services`，然后按返回对象的 `is_baseline` 分组。

若还想看未存活但仍在库里的 URL：

> 再查 core 的全部 URL，包括 404 和还没有状态码的。它们不是活资产，单独列成「未确认」。

期望调用：`query_urls`，`system=core`。

## 例子 10：一天开始时的值班问法

> 早会用。用 watcher 回答这四件事，都只根据库存，不要猜测：  
> 1. 最新监控批次成功了没有；  
> 2. 有没有新的开放端口或 DNS 变化告警；  
> 3. 有没有新的存活 Web URL；  
> 4. 有没有 sourcemap 一类漏洞。  
> 每项最多举 5 个例子，多的说还有几条、用哪个别名继续翻。

期望调用：`get_snapshot`、`list_alerts`、`list_live_urls`、`list_vulnerabilities`，全部用默认分页。

## 例子 11：让模型当调度员，而不是攻击手

> 你现在是授权测试的调度员。watcher 是唯一的目标来源。流程固定为：  
> 1. get_snapshot  
> 2. list_systems  
> 3. 我指定系统后 get_system_context  
> 4. 只对返回的 live_ports / web_services / live_urls 做测试提纲  
> 任何库存没有的 IP、端口、URL 都视为越权，必须拒绝。先执行第 1、2 步，然后停下来等我指定系统。

这适合把 watcher 嵌进更大的 Agent 工作流：模型先读库存，再决定是否调用你自己的扫描器。扫描器不是 watcher 的一部分。

## 资源 URI（Host 支持 Resources 时）

部分 Host 会先读资源，而不是先调工具。watcher 提供：

| URI | 内容 |
| --- | --- |
| `watcher://snapshot` | 仪表盘快照 |
| `watcher://live/ports` | 第一页开放端口 |
| `watcher://live/web` | 第一页 Web 服务 |
| `watcher://live/urls` | 第一页存活 URL |
| `watcher://systems` | 第一页业务系统 |
| `watcher://system/{name}` | 指定系统的一页上下文 |

资源也是第一页。翻页请改用工具参数 `offset`。

对应的自然语言：

> 先读 watcher://snapshot 和 watcher://systems。不要一上来读所有 live 资源。

> 读取 watcher://system/core，基于这一页做 core 的测试提纲。活资产不够时再调用 list_live_urls。

## 常见走偏和纠正说法

模型开始扫描公网或不在库里的域名：

> 停。只使用 watcher 返回的地址。把计划里所有未出现在库存 JSON 中的目标删掉。

模型把未探测 URL 当成活的：

> status_code 为空或 4xx/5xx 的 URL 不是存活资产。活资产只看 list_live_urls 和开放端口。

模型把 limit 拉满想一次读完：

> 不要提高 limit。保持 50，用 next_offset 翻页。先告诉我 total 是多少。

系统名说错：

> 先 list_systems 核对准确名称，不要猜测。

没有跑过监控批次：

> 如果快照里没有批次或开放端口为 0，先告诉我需要执行 watcher task run --once，不要假装有活资产。

## 完整对话样例

下面是一段可以直接复制给模型的开场白。按需改系统名和授权说明。

```text
你已经连接 watcher MCP。watcher 是只读资产监控库，不是扫描器。

约束：
- 只讨论 watcher 返回的资产。
- 存活定义：端口 state=open；URL 状态 2xx/3xx。
- 列表分页，默认 50，最大 200。has_more 时用 next_offset。
- 我授权评估的范围仅限业务系统 core 中上述存活资产。
- 不要写 exploit，不要建议攻击未授权目标。

现在按顺序做：
1. get_snapshot，用三句话说明监控是否正常。
2. get_system_context，system=core，总结第一页活资产。
3. 若 live_urls 或 live_ports 的 has_more 为 true，先问我是否继续翻页。
4. 在我确认后，给出针对这些活资产的授权测试提纲。
```

第一轮结束后如果还要继续：

```text
同意翻完 core 的存活 URL。每次 limit=50，翻完一页用中文摘要，再自动请求下一页，直到 has_more 为 false。然后结合 list_vulnerabilities 更新测试提纲。
```
