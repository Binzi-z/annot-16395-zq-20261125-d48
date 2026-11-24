"""记录 schema 与构造器。

为了让摘要、证明嵌入、落盘重放都最简单，所有事实/回执/提案都用
*JSON 可序列化的普通 dict* 表示，并在本模块集中定义字段约定与原因码。

双时态字段：
- ``vt``（valid time，有效时间）：该事实在现实中生效的逻辑时刻（整数 tick）。
- ``rt``（record / knowledge time，记录/到达时间）：裁决器实际收到该回执的时刻。
异地回执迟到 = 它的 ``rt`` 很大（可能在归档点之后），但其 ``vt`` 较早。

时间区间一律采用半开区间 ``[start, end)``：在 tick t 满足 ``start <= t < end``
才视为有效/未过期。这样“到期边界”无歧义，也便于逐 tick 暴力对照。
"""

from __future__ import annotations

from typing import Any, Iterable

from .hashing import digest_obj

# ---- 事实种类 -------------------------------------------------------------

ISOLATE = "ISOLATE"
EXTEND = "EXTEND"
APPROVAL = "APPROVAL"
AUTH_ROTATION = "AUTH_ROTATION"
REVOKE = "REVOKE"

FACT_KINDS = {ISOLATE, EXTEND, APPROVAL, AUTH_ROTATION, REVOKE}

# ---- 否决原因码（证明中机器可读） ----------------------------------------

E_NO_ISOLATION = "E_NO_ISOLATION"
E_DIGEST_MISMATCH = "E_DIGEST_MISMATCH"
E_EXTENSION_CHAIN_BROKEN = "E_EXTENSION_CHAIN_BROKEN"
E_NOT_TWO_APPROVALS = "E_NOT_TWO_APPROVALS"
E_SHARED_ROOT = "E_SHARED_ROOT"
E_APPROVAL_UNUSABLE = "E_APPROVAL_UNUSABLE"
E_AUTH_GENERATION_STALE = "E_AUTH_GENERATION_STALE"
E_WINDOW_NOT_OPEN = "E_WINDOW_NOT_OPEN"
E_WINDOW_EXPIRED = "E_WINDOW_EXPIRED"
E_REVOKED = "E_REVOKED"

# 裁决结论
ALLOW = "ALLOW"
DENY = "DENY"
NO_POINT = "NO_RECOVERABLE_POINT"

# 恢复暂存 FSM 结果
OUT_RESTORED = "RESTORED"
OUT_DECISION_STANDS_GAP = "DECISION_STANDS_RECEIPT_GAP"
OUT_REVOKED = "REVOKED"
OUT_DOUBT_ABORT = "ABORTED_IN_DOUBT"
OUT_DENIED = "DENIED"
OUT_DECIDED_NOT_APPLIED = "DECIDED_NOT_APPLIED"


class SchemaError(ValueError):
    pass


# ---- 事实构造器 -----------------------------------------------------------

def _base(kind: str, tenant_id: str, endpoint_id: str, vt: int) -> dict[str, Any]:
    if not isinstance(vt, int):
        raise SchemaError("vt 必须是整数 tick")
    return {
        "kind": kind,
        "tenant_id": tenant_id,
        "endpoint_id": endpoint_id,
        "vt": vt,
    }


def make_isolate(
    tenant_id: str,
    endpoint_id: str,
    vt: int,
    window_start: int,
    window_end: int,
    *,
    case_id: str | None = None,
) -> dict[str, Any]:
    f = _base(ISOLATE, tenant_id, endpoint_id, vt)
    if not (window_start <= window_end):
        raise SchemaError("窗口起点不得晚于终点")
    f["window"] = [window_start, window_end]
    if case_id is not None:
        f["case_id"] = case_id
    return f


def make_extend(
    tenant_id: str,
    endpoint_id: str,
    vt: int,
    root_isolation_digest: str,
    new_window_start: int,
    new_window_end: int,
    parent_digest: str | None = None,
) -> dict[str, Any]:
    f = _base(EXTEND, tenant_id, endpoint_id, vt)
    f["root_isolation_digest"] = root_isolation_digest
    f["parent_digest"] = parent_digest
    f["window"] = [new_window_start, new_window_end]
    return f


def make_approval(
    approval_id: str,
    tenant_id: str,
    endpoint_id: str,
    vt: int,
    approver: str,
    control_chain: list[str],
    auth_gen: int,
    valid_start: int,
    valid_end: int,
    *,
    bound_isolation_digest: str | None = None,
) -> dict[str, Any]:
    """control_chain 从 approver 起、逐级向上、以根控制人结尾。

    例如 ["a2", "ctrlX", "rootR"] 表示 a2 受 ctrlX 控制、最终根为 rootR。
    两个批准是否“独立”只比较解析出的根控制人。
    """
    f = _base(APPROVAL, tenant_id, endpoint_id, vt)
    if not control_chain or control_chain[0] != approver:
        raise SchemaError("control_chain 必须以 approver 自身开头且非空")
    f.update(
        approval_id=approval_id,
        approver=approver,
        control_chain=list(control_chain),
        root_controller=control_chain[-1],
        auth_gen=auth_gen,
        validity=[valid_start, valid_end],
    )
    if bound_isolation_digest is not None:
        f["bound_isolation_digest"] = bound_isolation_digest
    return f


def make_rotation(
    tenant_id: str, endpoint_id: str, vt: int, new_gen: int
) -> dict[str, Any]:
    f = _base(AUTH_ROTATION, tenant_id, endpoint_id, vt)
    f["new_gen"] = new_gen
    return f


def make_revoke(
    tenant_id: str, endpoint_id: str, vt: int, target_isolation_digest: str
) -> dict[str, Any]:
    f = _base(REVOKE, tenant_id, endpoint_id, vt)
    f["target_isolation_digest"] = target_isolation_digest
    return f


def event_digest(fact: dict[str, Any]) -> str:
    """原隔离事件摘要 = 对事实本体（不含回执外壳）的规范 SHA-256。"""
    return digest_obj(fact)


# ---- 回执外壳 -------------------------------------------------------------

def make_receipt(receipt_id: str, rt: int, fact: dict[str, Any]) -> dict[str, Any]:
    """把一个事实封装为分租户回执。

    回执分区键直接取 fact.tenant_id；event_digest 一并固化，便于核对。
    """
    return {
        "receipt_id": receipt_id,
        "tenant_id": fact["tenant_id"],
        "endpoint_id": fact["endpoint_id"],
        "rt": rt,
        "event_digest": event_digest(fact),
        "fact": fact,
    }


def receipt_digest(receipt: dict[str, Any]) -> str:
    """回执自身摘要（去掉可能附加的 receipt_digest 字段后计算）。"""
    body = {k: v for k, v in receipt.items() if k != "receipt_digest"}
    return digest_obj(body)


# ---- 恢复提案 -------------------------------------------------------------

def make_proposal(
    proposal_id: str,
    tenant_id: str,
    endpoint_id: str,
    at_vt: int,
    bound_isolation_digest: str,
    auth_gen: int,
    approval_ids: Iterable[str],
) -> dict[str, Any]:
    return {
        "proposal_id": proposal_id,
        "tenant_id": tenant_id,
        "endpoint_id": endpoint_id,
        "at_vt": at_vt,
        "bound_isolation_digest": bound_isolation_digest,
        "auth_gen": auth_gen,
        "approval_ids": list(approval_ids),
    }
