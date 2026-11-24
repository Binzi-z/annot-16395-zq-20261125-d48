"""双时态恢复裁决引擎（纯函数、标准库）。

两条时间轴
----------
- 有效时间 ``vt``：事实在现实中生效的时刻。
- 记录/到达时间 ``rt``：裁决器实际掌握该回执的时刻（知识时间）。

两种回看
--------
1. 按有效时间回看（retrospective）：``known_by_rt=None``，使用 *当前全部*
   回执（含迟到、归档后重放），只按 ``vt <= t`` 与区间覆盖过滤。它回答
   “沿有效历史看，t 时刻理论上是否可恢复”。
2. 按当时已知信息重放（known-then replay）：给定 ``known_by_rt=k``，只允许
   ``rt <= k`` 的回执；或用 :func:`earliest_actionable_time` 令判定时刻
   ``(at_vt=n, known_by_rt=n)``，求人们最早 *真正掌握足够信息* 的时刻。

恢复的五项必要条件（合取，全部满足才 ALLOW）
-------------------------------------------
C1 绑定 *原* 隔离事件摘要；扩展链锚定同一摘要。
C2 至少两个可用批准，且根控制人不同（同根 => E_SHARED_ROOT）。
C3 提案与每个批准的授权代都等于当前授权代。
C4 目标时刻落在未过期窗口 ``[start, end)`` 内。
C5 不存在已生效且当时已知的撤销。
"""

from __future__ import annotations

from typing import Any, Iterable

from .hashing import digest_obj
from .model import (
    ALLOW,
    APPROVAL,
    AUTH_ROTATION,
    DENY,
    EXTEND,
    ISOLATE,
    REVOKE,
    E_APPROVAL_UNUSABLE,
    E_AUTH_GENERATION_STALE,
    E_DIGEST_MISMATCH,
    E_EXTENSION_CHAIN_BROKEN,
    E_NO_ISOLATION,
    E_NOT_TWO_APPROVALS,
    E_REVOKED,
    E_SHARED_ROOT,
    E_WINDOW_EXPIRED,
    E_WINDOW_NOT_OPEN,
    event_digest,
)
from .roots import embedded_root

INF = None  # known_by_rt=None 表示知识截止为 +∞（当前全量）


# ---------------------------------------------------------------------------
# 去重与双时态选择
# ---------------------------------------------------------------------------

def dedupe_receipts(receipts: Iterable[dict]) -> tuple[list[dict], list[str], int]:
    """按 receipt_id 幂等去重。

    返回 ``(唯一回执(保留首次), 内容冲突的 id, 相同重放次数)``。
    相同 id 且规范摘要相同 => 归档后重放，幂等忽略；不同内容 => 冲突。
    """
    by_id: dict[str, dict] = {}
    conflicts: list[str] = []
    identical_replays = 0
    for r in receipts:
        rid = r["receipt_id"]
        if rid not in by_id:
            by_id[rid] = r
            continue
        if digest_obj(by_id[rid]) == digest_obj(r):
            identical_replays += 1
        else:
            if rid not in conflicts:
                conflicts.append(rid)
    return list(by_id.values()), conflicts, identical_replays


def _scoped_unique(receipts: Iterable[dict], tenant_id: str, endpoint_id: str):
    # 先按分区(租户)+端点裁剪，再在 *该范围之内* 按 receipt_id 幂等去重。
    # 不能先做全局 id 去重：否则跨租户恰好相同的 receipt_id 会在“读全部分区”
    # 路径上互相遮蔽（dedupe 只留第一条），从而造成“只读该租户分区”与“读全量
    # 所有分区”结果不一致——这正是分区裁剪核对要杜绝的问题。
    raw_scoped = [
        r
        for r in receipts
        if r.get("tenant_id") == tenant_id and r.get("endpoint_id") == endpoint_id
    ]
    scoped, conflicts, replays = dedupe_receipts(raw_scoped)
    return scoped, conflicts, replays


def _knowledge_visible(scoped: list[dict], known_by_rt: int | None) -> list[dict]:
    if known_by_rt is None:
        return list(scoped)
    return [r for r in scoped if r["rt"] <= known_by_rt]


def _eligible(visible: list[dict], at_vt: int) -> list[dict]:
    return [r for r in visible if r["fact"]["vt"] <= at_vt]


def _rule(rule: str, passed: bool, reason_code: str | None = None, **detail: Any) -> dict:
    return {
        "rule": rule,
        "passed": passed,
        "reason_code": reason_code,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# 各条件
# ---------------------------------------------------------------------------

def _find_bound_isolate(eligible: list[dict], bound_digest: str):
    iso_receipts = [r for r in eligible if r["fact"]["kind"] == ISOLATE]
    for r in iso_receipts:
        if event_digest(r["fact"]) == bound_digest:
            return r, iso_receipts
    return None, iso_receipts


def _extension_chain_ok(eligible: list[dict], bound_digest: str) -> tuple[bool, list[str]]:
    """校验所有锚定该原隔离的扩展：root 摘要必须一致；若给了 parent_digest，
    则必须能在同链的 isolate/extend 摘要中找到。"""
    known_digests = {
        event_digest(r["fact"])
        for r in eligible
        if r["fact"]["kind"] in (ISOLATE, EXTEND)
    }
    for r in eligible:
        f = r["fact"]
        if f["kind"] != EXTEND:
            continue
        if f.get("root_isolation_digest") != bound_digest:
            continue  # 属于别的隔离链，不在本绑定范围内
        if f.get("parent_digest") is not None and f["parent_digest"] not in known_digests:
            return False, [event_digest(f)]
    return True, []


def _current_gen(eligible: list[dict]) -> int:
    gens = [r["fact"]["new_gen"] for r in eligible if r["fact"]["kind"] == AUTH_ROTATION]
    return max([1, *gens])


def _effective_window(eligible: list[dict], bound_digest: str):
    cands = []
    for r in eligible:
        f = r["fact"]
        if f["kind"] == ISOLATE and event_digest(f) == bound_digest:
            cands.append(r)
        elif f["kind"] == EXTEND and f.get("root_isolation_digest") == bound_digest:
            cands.append(r)
    if not cands:
        return None, None
    # 有效时间最晚者胜；同 vt 用 (rt, receipt_id) 确定地打破平局。
    pick = max(cands, key=lambda r: (r["fact"]["vt"], r["rt"], r["receipt_id"]))
    return pick["fact"].get("window"), pick


def _root_controller_of(fact: dict, resolver) -> str:
    """根控制人：显式给了 RootResolver 边表时以边表为准，否则用内嵌控制链。

    这样裁决器既能凭批准回执里自包含的 ``control_chain`` 在单租户分区内自证，
    也能接受调用方提供的外部控制关系解析器。
    """
    if resolver is not None:
        return resolver.root_of(fact["approver"])
    return embedded_root(fact)


def _approval_detail(
    approval_id: str,
    scoped: list[dict],
    visible_ids: set[str],
    at_vt: int,
    current_gen: int,
    resolver=None,
) -> dict:
    rec = None
    for r in scoped:
        f = r["fact"]
        if f["kind"] == APPROVAL and f.get("approval_id") == approval_id:
            rec = r
            break
    base = {"approval_id": approval_id, "present_in_store": rec is not None}
    if rec is None:
        base.update(usable=False, availability="ABSENT")
        return base
    f = rec["fact"]
    lo, hi = f.get("validity", [0, 0])
    known = rec["receipt_id"] in visible_ids
    effective = f["vt"] <= at_vt
    covers = lo <= at_vt < hi
    gen_ok = f.get("auth_gen") == current_gen
    problems = []
    if not known:
        problems.append("NOT_KNOWN_BY_CUTOFF")
    if not effective:
        problems.append("NOT_EFFECTIVE_YET")
    if at_vt < lo:
        problems.append("VALIDITY_NOT_OPEN")
    if at_vt >= hi:
        problems.append("APPROVAL_EXPIRED")
    if not gen_ok:
        problems.append("AUTH_GEN_MISMATCH")
    usable = known and effective and covers and gen_ok
    base.update(
        usable=usable,
        root_controller=_root_controller_of(f, resolver),
        approver=f.get("approver"),
        auth_gen=f.get("auth_gen"),
        current_gen=current_gen,
        known_by_cutoff=known,
        receipt_id=rec["receipt_id"],
        event_digest=event_digest(f),
        problems=problems,
    )
    return base


# ---------------------------------------------------------------------------
# 主裁决
# ---------------------------------------------------------------------------

def evaluate(
    proposal: dict[str, Any],
    receipts: Iterable[dict],
    *,
    at_vt: int | None = None,
    known_by_rt: int | None = None,
    resolver=None,
) -> dict[str, Any]:
    """对一个恢复提案在指定双时态坐标下裁决。返回纯 JSON 可序列化 Verdict。"""
    t = proposal["at_vt"] if at_vt is None else at_vt
    tenant = proposal["tenant_id"]
    endpoint = proposal["endpoint_id"]

    scoped, conflicts, replays = _scoped_unique(receipts, tenant, endpoint)
    visible = _knowledge_visible(scoped, known_by_rt)
    visible_ids = {r["receipt_id"] for r in visible}
    eligible = _eligible(visible, t)

    conditions: list[dict] = []
    evidence_ids: set[str] = set()

    # ---- C1 原隔离摘要绑定 ------------------------------------------------
    iso_all = [r for r in eligible if r["fact"]["kind"] == ISOLATE]
    bound_rec, _ = _find_bound_isolate(eligible, proposal["bound_isolation_digest"])
    if not iso_all:
        c1 = _rule(
            "bind_original_isolation_digest", False, E_NO_ISOLATION,
            bound=proposal["bound_isolation_digest"],
        )
    elif bound_rec is None:
        c1 = _rule(
            "bind_original_isolation_digest", False, E_DIGEST_MISMATCH,
            bound=proposal["bound_isolation_digest"],
            available_digests=[event_digest(r["fact"]) for r in iso_all],
        )
        for r in iso_all:
            evidence_ids.add(r["receipt_id"])
    else:
        chain_ok, broken = _extension_chain_ok(eligible, proposal["bound_isolation_digest"])
        evidence_ids.add(bound_rec["receipt_id"])
        if not chain_ok:
            c1 = _rule(
                "bind_original_isolation_digest", False, E_EXTENSION_CHAIN_BROKEN,
                bound=proposal["bound_isolation_digest"], broken=broken,
            )
        else:
            c1 = _rule(
                "bind_original_isolation_digest", True,
                bound=proposal["bound_isolation_digest"],
            )
    conditions.append(c1)

    # ---- C3 先算当前授权代（C2 细节也要用） -------------------------------
    current_gen = _current_gen(eligible)
    gen_passed = proposal.get("auth_gen") == current_gen
    c3 = _rule(
        "current_authorization_generation", gen_passed,
        None if gen_passed else E_AUTH_GENERATION_STALE,
        proposed_gen=proposal.get("auth_gen"), current_gen=current_gen,
    )
    for r in eligible:
        if r["fact"]["kind"] == AUTH_ROTATION:
            evidence_ids.add(r["receipt_id"])
    conditions.append(c3)

    # ---- C2 两个独立批准 --------------------------------------------------
    approval_details = [
        _approval_detail(aid, scoped, visible_ids, t, current_gen, resolver)
        for aid in proposal.get("approval_ids", [])
    ]
    usable = [d for d in approval_details if d.get("usable")]
    for d in approval_details:
        if d.get("receipt_id"):
            # 只把当时可见的批准作为证据；不可见的无法嵌入。
            if d["receipt_id"] in visible_ids:
                evidence_ids.add(d["receipt_id"])

    if len(usable) < 2:
        c2 = _rule(
            "two_independent_approvals", False, E_NOT_TWO_APPROVALS,
            usable_count=len(usable), required=2, approvals=approval_details,
        )
    else:
        roots = [d["root_controller"] for d in usable]
        # 存在两个根不同的可用批准即满足；否则所有可用批准同根。
        independent = len(set(roots)) >= 2
        if independent:
            c2 = _rule(
                "two_independent_approvals", True,
                usable_count=len(usable), roots=sorted(set(roots)),
                approvals=approval_details,
            )
        else:
            c2 = _rule(
                "two_independent_approvals", False, E_SHARED_ROOT,
                shared_root=roots[0], roots=roots, approvals=approval_details,
            )
    conditions.append(c2)

    # ---- C4 未过期窗口 ----------------------------------------------------
    window, win_rec = _effective_window(eligible, proposal["bound_isolation_digest"])
    if win_rec is not None:
        evidence_ids.add(win_rec["receipt_id"])
    if window is None:
        c4 = _rule(
            "restore_window", False, E_WINDOW_EXPIRED,
            reason_detail="NO_WINDOW_RECORD", at_vt=t,
        )
    else:
        s, e = window
        if t < s:
            c4 = _rule("restore_window", False, E_WINDOW_NOT_OPEN,
                       window=[s, e], at_vt=t)
        elif t >= e:
            c4 = _rule("restore_window", False, E_WINDOW_EXPIRED,
                       window=[s, e], at_vt=t)
        else:
            c4 = _rule("restore_window", True, window=[s, e], at_vt=t)
    conditions.append(c4)

    # ---- C5 撤销 ----------------------------------------------------------
    revokes = [
        r for r in eligible
        if r["fact"]["kind"] == REVOKE
        and r["fact"].get("target_isolation_digest") == proposal["bound_isolation_digest"]
    ]
    for r in revokes:
        evidence_ids.add(r["receipt_id"])
    c5 = _rule(
        "not_revoked", len(revokes) == 0,
        None if not revokes else E_REVOKED,
        revoke_receipt_ids=[r["receipt_id"] for r in revokes],
    )
    conditions.append(c5)

    # 规范条件顺序：C1, C2, C3, C4, C5（把 C2 插到 C1 后、C3 前展示）
    ordered = [conditions[0], conditions[2], conditions[1], conditions[3], conditions[4]]
    failed = [c for c in ordered if not c["passed"]]
    allowed = not failed

    # 自包含证据：当时知识截止下该终端的全部唯一回执（已含上述 id）。
    evidence_receipts = sorted(visible, key=lambda r: r["receipt_id"])

    return {
        "allowed": allowed,
        "decision": ALLOW if allowed else DENY,
        "primary_reason": failed[0]["reason_code"] if failed else None,
        "failed_rules": [
            {"rule": c["rule"], "reason_code": c["reason_code"]} for c in failed
        ],
        "conditions": ordered,
        "view": {
            "tenant_id": tenant,
            "endpoint_id": endpoint,
            "at_vt": t,
            "known_by_rt": known_by_rt,
        },
        "proposal": proposal,
        "evidence_receipt_ids": sorted(evidence_ids),
        "evidence_receipts": evidence_receipts,
        "replay": {
            "identical_replays_deduped": replays,
            "conflicting_receipt_ids": conflicts,
        },
    }


# ---------------------------------------------------------------------------
# 最早可恢复点
# ---------------------------------------------------------------------------

def _candidate_valid_times(scoped: list[dict]) -> list[int]:
    cands: set[int] = {0}
    for r in scoped:
        f = r["fact"]
        cands.add(f["vt"])
        if "window" in f:
            s, e = f["window"]
            cands.update((s, e))
        if "validity" in f:
            s, e = f["validity"]
            cands.update((s, e))
    return sorted(cands)


def earliest_by_valid_time(
    proposal: dict[str, Any], receipts: Iterable[dict], *, resolver=None
) -> dict[str, Any]:
    """按有效时间回看（知识截止=+∞）求最早可恢复的有效时刻。

    谓词只在事件/区间边界翻转，故只需枚举这些候选 tick；测试中另有逐 tick
    暴力扫描证明该边界法与穷举结果一致。
    """
    scoped, _, _ = _scoped_unique(
        receipts, proposal["tenant_id"], proposal["endpoint_id"]
    )
    last = None
    for t in _candidate_valid_times(scoped):
        v = evaluate(proposal, receipts, at_vt=t, known_by_rt=None, resolver=resolver)
        last = v
        if v["allowed"]:
            return {"earliest": t, "verdict": v, "semantics": "VALID_TIME_RETROSPECTIVE"}
    return {"earliest": None, "verdict": last, "semantics": "VALID_TIME_RETROSPECTIVE"}


def evaluate_known_then(
    proposal: dict[str, Any], receipts: Iterable[dict], at_time: int, *, resolver=None
) -> dict[str, Any]:
    """“当时”重放：在时刻 at_time，只能用 rt<=at_time 到达、vt<=at_time 生效的信息。"""
    return evaluate(
        proposal, receipts, at_vt=at_time, known_by_rt=at_time, resolver=resolver
    )


def earliest_actionable_time(
    proposal: dict[str, Any], receipts: Iterable[dict], *, resolver=None
) -> dict[str, Any]:
    """求人们最早 *实际掌握所需信息* 并可当即恢复的“当时”时刻 n。

    坐标固定为 ``at_vt=n, known_by_rt=n``。状态只在回执到达(rt)或有效边界
    (vt/区间端点)变化，故枚举这些候选时刻。
    """
    scoped, _, _ = _scoped_unique(
        receipts, proposal["tenant_id"], proposal["endpoint_id"]
    )
    cands: set[int] = {0}
    for r in scoped:
        cands.add(r["rt"])
        f = r["fact"]
        cands.add(f["vt"])
        if "window" in f:
            cands.update(f["window"])
        if "validity" in f:
            cands.update(f["validity"])
    last = None
    for n in sorted(cands):
        v = evaluate(proposal, receipts, at_vt=n, known_by_rt=n, resolver=resolver)
        last = v
        if v["allowed"]:
            return {"earliest": n, "verdict": v, "semantics": "KNOWN_THEN_REPLAY"}
    return {"earliest": None, "verdict": last, "semantics": "KNOWN_THEN_REPLAY"}


def brute_force_earliest_tick(
    proposal: dict[str, Any],
    receipts: Iterable[dict],
    horizon: int,
    *,
    known_then: bool = False,
    known_by_rt: int | None = None,
) -> int | None:
    """独立的逐 tick 暴力预言机：扫描 0..horizon，返回第一个 ALLOW 的 tick。

    测试用它核对候选边界法。``known_then=True`` 时坐标为 (t, known_by=t)。
    """
    for t in range(0, horizon + 1):
        k = t if known_then else known_by_rt
        v = evaluate(proposal, receipts, at_vt=t, known_by_rt=k)
        if v["allowed"]:
            return t
    return None
