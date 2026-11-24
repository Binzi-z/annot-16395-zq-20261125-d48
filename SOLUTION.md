# 双时态恢复裁决器（Windows / Python 3.12 标准库）

安全演练的离线裁决器。同一合成终端可 **隔离 → 延长隔离 → 按批准恢复**，异地回执会
**迟到并在归档后重放**。本实现零第三方依赖，只用 Python 3.12 标准库。

## 运行

在本目录（含 `solution.py` 的 `作答工作区_cc-16395-20261125-r1/`）下：

```bat
python solution.py
```

它会依次跑完四类核对并在 `artifacts/` 写出 `demo_report.json`、`sample_veto_proof.json`
和真实 fsync 屏障演练目录；全部通过时退出码为 `0`。

测试套件：

```bat
python -m unittest -v test_adjudicator
```

> 若 Windows 控制台编码报错，可先 `set PYTHONUTF8=1`（代码内部也已尝试把 stdout 重配为 UTF-8）。

## 题面要求 → 实现/验证位置

| 要求 | 实现 | 验证 |
|---|---|---|
| 恢复绑定 **原隔离事件摘要** | `engine.evaluate` C1，`model.event_digest`（规范 JSON + SHA-256） | 精选 `digest_mismatch`、决策表、`VetoProofTests` |
| **独立批准**；两个批准同一根控制人不满足 | `roots.py` 沿控制链/控制边表解析根（带环检测）；C2 要求 ≥2 个可用且根不同 | `same_root` 剧本、`RootIndependenceTests`、决策表 |
| 绑定 **当前授权代** | `AUTH_ROTATION` 单调推进 `current_gen`；提案与每个批准都必须等于当前代（C3） | `stale_gen`、决策表 |
| 绑定 **未过期窗口** | 半开区间 `[start,end)`，取最晚生效的隔离/延长窗口（C4） | `late_expired`、决策表 |
| 区分 **按有效时间回看** 与 **按当时已知信息重放** | 双时态坐标 `(at_vt, known_by_rt)`：`earliest_by_valid_time`（知识截止 ∞）vs `evaluate_known_then` / `earliest_actionable_time`（`at_vt=known_by=n`） | `gold_late_in_window`：有效时间最早 **12**，实际可知最早 **60**；归档点 40 否决 |
| 输出 **最早可恢复点** | 只在事件/区间/到达边界上枚举候选时刻 | `check_earliest_bruteforce` 与逐 tick 暴力预言机完全一致 |
| **可验证的否决证明** | `proof.py`：自包含证据 + 无序集合 Merkle 承诺 + 哈希链 + HMAC 封签 + **重跑规则的逻辑复核** | 全部否决证明 `verify_proof` 通过；篡改摘要、持密钥“重新封签的逻辑谎言”都被识破 |
| **屏障 + 故障点** 复测 | `durable.py`：`BarrierLog`（append→`barrier` 才落 stable）、`FaultInjector` 编号故障点；另有 `FileBarrierLog` 用 `flush+os.fsync` 真实落盘 | `BarrierFaultPointTests`、`FileFsyncBarrierTests` |
| **撤销正好落盘** | 故障点 `revoke.post_barrier`：REVOKE 已越 fsync 屏障 → 恢复判 `REVOKED` | 精确点测试 + 穷举定位 + 真实文件 A 场景 |
| **回执已丢但决定已落盘** | 故障点 `receipt.post_append`：回执未越屏障崩溃丢失，DECISION(APPROVE) 已落盘 → `DECISION_STANDS_RECEIPT_GAP`（决定成立、报证据缺口、不翻案） | 精确点测试 + 穷举定位 + 真实文件 B 场景 |
| **短序列独立穷举** | `exhaustive.enumerate_crash_sequences`：5 个操作 × 长度 1..4 共 780 个序列，每个序列独立扫过其 **每一个故障点**（数千次），用直接读 stable 原始记录的安全预言机核对 I1–I5 | `test_short_sequences_*` |
| **≥6 万条分租户回执** | `synth.generate_bulk` 确定性生成 **8 租户 ×1000 终端 ×8 = 64000** 条，每终端带已知期望结论 | `ScalePartitionTests` |
| **局部更正实际访问分区与全量一致** | `partitions.audit_local_correction`：审计 `accessed`，并比对局部结果 vs 读全部分区结果、全量重扫语义变化租户集合 | `test_local_correction_*`：实际访问恰为 `{t00}`，全量语义变化租户也恰为 `{t00}`，结果一致 |

## 关键语义

- **双时态**：`vt` 是事实在现实中生效的有效时间，`rt` 是裁决器实际收到回执的知识/记录时间。
  迟到回执 `rt` 大、`vt` 早：按有效时间回看它“早就能恢复”，但回到历史当时，人们因 `rt` 未到而
  **不可能** 知道它——两种答案都被显式计算并分别给出最早点。
- **幂等重放**：相同 `receipt_id` + 相同规范摘要的归档后重放只计一次；同 id 不同内容标记为冲突。
- **崩溃安全不变量**：
  - I1 任何 `APPLIED` 之前必有 `APPROVE` 决定，且 `APPLIED` 之前不得有 durable `REVOKE`；
  - I2 判为 `RESTORED` ⇔ 日志存在合法 `APPLIED`；
  - I3 有 durable `REVOKE` 且无合法 `APPLIED` ⇒ 必为 `REVOKED`；
  - I4 `DECISION_STANDS_RECEIPT_GAP` ⇒ 必有 `APPROVE` 且所需回执不在 stable；
  - I5 同一 stable 日志的恢复结论确定可重复。
- **决定不可翻案 vs 安全优先**：已 fsync 的 `DECISION` 作为裁决事实不可被后来回执改写；但若撤销
  先于实际效果点 `APPLY` 落盘，安全闸阻止执行恢复，结论为 `REVOKED`（同时保留 `durable_verdict=APPROVE`
  与 `post_decision_revoke=True`）。若 `APPLIED` 已落盘后撤销才到，则是“恢复后再撤销/再隔离”，
  不追溯成从未恢复。

## 目录

```
solution.py                 一键入口
test_adjudicator.py         unittest 全套独立核对
adjudicator/
  hashing.py                规范 JSON / SHA-256 / Merkle / 哈希链 / HMAC
  model.py                  schema、原因码、构造器、双时态时间约定
  roots.py                  根控制人解析与独立性
  engine.py                 双时态裁决 + 最早点 + 逐 tick 预言机
  proof.py                  可验证否决证明 build/verify
  durable.py                屏障/故障点 FSM、崩溃恢复、真实 fsync 文件日志
  exhaustive.py             决策表 + 最早点对照 + 短序列×故障点穷举
  partitions.py             分区存储/访问审计/局部更正 vs 全量
  synth.py                  确定性精选剧本 + 64000 条回执
  demo.py                   端到端报告
```

> 信任边界说明：否决证明能自证“给定嵌入证据，否决成立且证据/结论未被篡改”。
> “当时是否被隐瞒了 `rt<=k` 的回执”属于日志完整性，由分租户分区 Merkle 承诺与
> 64000 条全量重扫/局部更正核对来锚定。演示 HMAC 密钥是合成常量；真实部署应改从
> DPAPI/密钥保管读取（`.gitignore` 已排除 `*.key/*.dpapi`）。
