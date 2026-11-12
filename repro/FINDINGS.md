# pip-audit：空漏洞列表的语义与服务超时排查

复现方式完全离线：用**假时钟**（替换 `cachecontrol.controller.time.time`）和
**脚本化 HTTP 适配器**（继承真实 `CacheControlAdapter`，仅替换网络收发）驱动
pip-audit 真实的缓存（`FileCache` + `CacheController`）、服务（PyPI/OSV/ESMS）
和 JSON 格式化代码。入口：

- `repro/harness.py`：假时钟 + 脚本化传输（缓存/序列化/新鲜度判断均为真实实现）
- `repro/run_scenarios.py`：服务层五类条件的逐条复现
- `repro/run_cli.py`：多包场景下，按 `_cli.py` 真实审计循环复现退出码与 JSON

## 1. 缓存链路（为什么会出现“空列表”）

`PyPIService/OsvService` 都通过 `pip_audit._cache.caching_session()` 拿到一个
`CacheControl` 会话，落盘到 `FileCache`。新鲜度由
`cachecontrol/controller.py` 的 `cached_request()` 判定：

- 读取响应 `Date`，`current_age = time.time() - date`；
- 取 `Cache-Control: max-age`（或 `Expires`）作为 `freshness_lifetime`；
- `freshness_lifetime > current_age` 才直接返回缓存，**不发网络请求**；
- 否则视为过期，带条件头重新向服务查询。

因此“缓存命中”与“真的查到无漏洞”在数据上是同一种成功结果，而查询失败走的是
完全不同的异常路径——旧代码却没有把这两者在输出里区分开。

## 2. 空漏洞列表的三种来源（关键结论）

| 来源 | 依赖对象类型 | 旧 JSON 形态 | 是否拿到有效查询结果 |
|---|---|---|---|
| 服务返回 200，确无漏洞（含新鲜缓存命中） | `ResolvedDependency` | `{"name","version","vulns":[]}` | 是，已查询且干净 |
| PyPI 返回 404（包/版本不存在） | `SkippedDependency` | `{"name","skip_reason"}`，无 `vulns` | 否，服务明确“不知道” |
| 429 / 5xx / 连接超时 / 报文损坏 | 抛出 `ServiceError`/`ConnectionError` | **不产生该包条目** | 否，根本没拿到结果 |

旧实现的根本问题在第三行：`query()` 抛出的异常在 `Auditor.audit()` 与
`_cli.py` 的循环里都没有按包捕获。

- `ConnectionError` 被 `_cli.py` 捕获后 `_fatal()` → `sys.exit(1)`；
- 其它 `ServiceError`（429、5xx、畸形版本等）**完全未捕获**，以未处理异常终止，
  退出码同样是 1。

两种情况下整个审计立即中断，**排在失败包之后的包永远不会被查询**；已经处理过的
包留在内存 `result` 里，但因为进程异常退出，清单 JSON 根本不会写出。这正是
“一次服务超时后，审计 JSON 里只剩若干包、且看起来都是空漏洞列表”的成因——
留下的空列表是“已查询且干净”，而真正没查到结果的包是**缺失**，无法从 JSON 分辨。

## 3. 五类条件的实际表现（修复前 → 修复后）

服务层单包（`repro/run_scenarios.py`）：

| 条件 | 缓存/网络行为 | 修复前 | 修复后 |
|---|---|---|---|
| 有效（新鲜）缓存 | 首次 200 落盘；时钟前进 50s 后二次查询 0 次网络命中 | 返回 `vulns:[]`，成功 | `audit_status=success`，`has_vulnerability_result=true` |
| 过期缓存 + 503 | 时钟前进 500s 触发重验证，再次发网络请求并失败 | `ServiceError` 冒泡、终止 | `query()` 仍抛错；`query_all()` 转为 `error` 跳过，不信任陈旧缓存 |
| 404 | 服务返回 404 | `SkippedDependency`（无 `vulns`） | `audit_status=not_known`，`has_vulnerability_result=false` |
| 429 限流 | 服务返回 429 | `ServiceError` 冒泡、终止 | `query_all()` 转为 `error` 跳过 |
| 5xx（500/503） | 服务返回 5xx | `ServiceError` 冒泡、终止 | `query_all()` 转为 `error` 跳过 |
| 连接超时 | `requests.ConnectTimeout` | `ConnectionError` → `_fatal` 退出 1 | 同上，按包转为 `error` 跳过 |

多包审计（`repro/run_cli.py`，alpha/beta/gamma，中间包失败）：

| 场景 | 修复前退出码 | 修复前 JSON | 修复后退出码 | 修复后 JSON |
|---|---|---|---|---|
| 全部 200 干净 | 0 | 三个 `vulns:[]` | 0 | 三个 `success`，`coverage.complete=true` |
| beta 404 | 0 | beta 仅 `skip_reason` | 0 | beta `not_known`，`coverage.complete=false` |
| beta 500 | 1 | **无 JSON**，gamma 缺失 | 0（非 strict） | 三包齐全，beta `error`，gamma 仍 `success` |
| beta 429 | 1 | **无 JSON**，gamma 缺失 | 0（非 strict） | 三包齐全，beta `error` |

`--strict` 下任何跳过（含 `error`）仍按原语义 `sys.exit(1)`；非 strict 下错误类跳过
以 `logger.error` 显著记录，但不中断其余包的审计。

## 4. 修复后 JSON 如何明确每个包的结果

每个依赖条目新增两个字段：

- `audit_status`：`success` / `not_known` / `error`
- `has_vulnerability_result`：布尔，只有 `success` 为 `true`

顶层新增 `coverage` 汇总：`total`、`valid_query_result`、`not_known`、`error`、
`complete`。据此可机械判断：空 `vulns` 仅在 `audit_status=success` 时表示
“查过且无漏洞”；`not_known/error` 表示“没拿到有效结果”，绝不能读作干净。

```json
{
  "dependencies": [
    {"name": "alpha", "version": "1.0.0", "audit_status": "success",
     "has_vulnerability_result": true, "vulns": []},
    {"name": "beta", "audit_status": "error",
     "has_vulnerability_result": false,
     "skip_reason": "Failed to query vulnerability service: PyPI returned an unexpected response (HTTP 500)"}
  ],
  "fixes": [],
  "coverage": {"total": 2, "valid_query_result": 1, "not_known": 0,
               "error": 1, "complete": false}
}
```

## 5. 代码改动落点

- `pip_audit/_service/interface.py`：新增 `AuditStatus` 枚举；`Dependency.audit_status`
  默认 `success`，`SkippedDependency` 携带显式状态；`query_all()` 按包捕获
  `ServiceError` 并转为 `AuditStatus.Error` 跳过（不再让单包失败终止整轮）。
- `pip_audit/_service/pypi.py`：404 显式标记 `NotKnown`；其它 HTTP 错误的
  `ServiceError` 带上状态码。
- `pip_audit/_service/osv.py`、`esms.py`：HTTP 错误信息带上状态码。
- `pip_audit/_format/json.py`：每条目输出 `audit_status`/`has_vulnerability_result`，
  顶层输出 `coverage`。
- `pip_audit/_cli.py`：非 strict 模式对 `error` 跳过以 error 级日志记录，审计继续。

## 6. 验证

- 新增 `test/service/test_query_status.py`（假时钟 + 脚本 HTTP，覆盖新鲜缓存、过期
  缓存重验证失败、404、429、500、503、失败后续跑）与
  `test/format/test_json_status.py`（状态区分与 coverage）。
- 更新 `test/service/test_pypi.py`、`test/format/test_json.py` 以匹配新契约。
- 离线全量测试：相对基线**无新增失败**；剩余失败均为沙箱环境问题
  （默认缓存目录不可写、`pip` 子进程/网络被禁），与本次改动无关。
