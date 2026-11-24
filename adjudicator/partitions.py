"""分租户分区存储、实际访问分区审计、局部更正 vs 全量一致性核对。

关键能力
--------
- 所有回执按 ``tenant_id`` 物理分区存放。
- 每次读分区都记录到 ``accessed``，从而能回答“局部更正到底访问了哪些分区”。
- 根控制人链内嵌在批准回执中，因此单租户分区即可完成裁决，不依赖全局控制表，
  这是“分区裁剪正确”的前提。
- :func:`audit_local_correction` 同时证明三件事严格一致：
  1. 局部重算（只读目标租户分区）的详细结果 == 读全量所有分区的结果；
  2. 局部路径 *实际访问分区* 恰好 == 计划的 ``{目标租户}``（不多读、不漏读）；
  3. 对全量 6 万+回执重扫后，裁决语义发生变化的租户集合也恰好 == ``{目标租户}``。
"""

from __future__ import annotations

from typing import Any, Iterable

from .engine import earliest_actionable_time, earliest_by_valid_time, evaluate
from .hashing import digest_obj, set_commitment


class PartitionedStore:
    def __init__(self) -> None:
        self._partitions: dict[str, list[dict[str, Any]]] = {}
        self.accessed: set[str] = set()
        self.written: set[str] = set()

    # -- 写入 ---------------------------------------------------------------

    def add(self, receipt: dict[str, Any]) -> None:
        t = receipt["tenant_id"]
        self._partitions.setdefault(t, []).append(receipt)
        self.written.add(t)

    def add_many(self, receipts: Iterable[dict[str, Any]]) -> None:
        for r in receipts:
            self.add(r)

    def replace_receipt(self, tenant: str, receipt_id: str, new_receipt: dict) -> bool:
        part = self._partitions.get(tenant, [])
        for i, r in enumerate(part):
            if r["receipt_id"] == receipt_id:
                part[i] = new_receipt
                self.written.add(tenant)
                return True
        return False

    # -- 读取（全部记录访问审计） ------------------------------------------

    def read(self, tenant: str) -> list[dict[str, Any]]:
        self.accessed.add(tenant)
        return list(self._partitions.get(tenant, []))

    def read_many(self, tenants: Iterable[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for t in tenants:
            out.extend(self.read(t))
        return out

    def read_all(self) -> list[dict[str, Any]]:
        for t in self._partitions:
            self.accessed.add(t)
        out: list[dict[str, Any]] = []
        for t in self._partitions:
            out.extend(self._partitions[t])
        return out

    def endpoint_receipts(self, tenant: str, endpoint: str) -> list[dict[str, Any]]:
        self.accessed.add(tenant)  # 端点索引仍是在该租户分区内访问
        return [
            r
            for r in self._partitions.get(tenant, [])
            if r.get("endpoint_id") == endpoint
        ]

    def reset_access_audit(self) -> None:
        self.accessed.clear()

    # -- 规模 / 承诺 --------------------------------------------------------

    def tenants(self) -> list[str]:
        return sorted(self._partitions)

    def size(self, tenant: str | None = None) -> int:
        if tenant is not None:
            return len(self._partitions.get(tenant, []))
        return sum(len(v) for v in self._partitions.values())

    def partition_commitment(self, tenant: str) -> str:
        return set_commitment([digest_obj(r) for r in self._partitions.get(tenant, [])])

    def partition_counts(self) -> dict[str, int]:
        return {t: len(rs) for t, rs in sorted(self._partitions.items())}


# ---------------------------------------------------------------------------
# 结果摘要
# ---------------------------------------------------------------------------

def detailed_endpoint_result(proposal: dict, receipts: Iterable[dict]) -> dict[str, Any]:
    """对一个端点计算完整双时态结果（当前裁决 + 两个最早点）。纯函数。"""
    at_v = evaluate(proposal, receipts, at_vt=proposal["at_vt"])
    early_vt = earliest_by_valid_time(proposal, receipts)
    early_known = earliest_actionable_time(proposal, receipts)
    return {
        "decision": at_v["decision"],
        "primary_reason": at_v["primary_reason"],
        "failed_rules": at_v["failed_rules"],
        "at_vt": proposal["at_vt"],
        "earliest_valid_time": early_vt["earliest"],
        "earliest_actionable": early_known["earliest"],
    }


def result_digest(result: dict[str, Any]) -> str:
    return digest_obj(result)


def _light_summary(proposal: dict, receipts: Iterable[dict]) -> dict[str, Any]:
    v = evaluate(proposal, receipts, at_vt=proposal["at_vt"])
    return {"decision": v["decision"], "primary_reason": v["primary_reason"]}


def tenant_semantic_digest(
    store: PartitionedStore, proposals: Iterable[dict]
) -> dict[str, str]:
    """全量语义摘要：按提案逐端点裁决，再汇总成每租户一个稳定摘要。

    单次扫描全部分区并按端点分组（O(回执数 + 提案数)），避免对每端点重复
    扫描整个租户分区造成平方复杂度。
    """
    store.accessed.update(store.tenants())  # 语义摘要是一次全分区扫描
    grouped: dict[tuple[str, str], list[dict]] = {}
    for tenant in store.tenants():
        for r in store.read(tenant):
            grouped.setdefault((r["tenant_id"], r["endpoint_id"]), []).append(r)

    per_tenant: dict[str, list[tuple[str, str]]] = {}
    for p in proposals:
        rs = grouped.get((p["tenant_id"], p["endpoint_id"]), [])
        s = _light_summary(p, rs)
        per_tenant.setdefault(p["tenant_id"], []).append(
            (p["endpoint_id"], digest_obj(s))
        )
    out: dict[str, str] = {}
    for t, items in per_tenant.items():
        items.sort()
        out[t] = set_commitment([h for _, h in items])
    return out


# ---------------------------------------------------------------------------
# 局部更正核对
# ---------------------------------------------------------------------------

def audit_local_correction(
    store: PartitionedStore,
    proposals: list[dict],
    *,
    tenant: str,
    endpoint: str,
    proposal: dict,
    target_receipt_id: str,
    corrected_receipt: dict,
) -> dict[str, Any]:
    """应用一次局部更正并核对“访问分区 / 局部结果 / 全量结果”三者一致。"""
    # 1) 更正前全量语义基线
    store.reset_access_audit()
    before = tenant_semantic_digest(store, proposals)

    # 2) 执行局部更正（只写目标租户分区）
    ok = store.replace_receipt(tenant, target_receipt_id, corrected_receipt)
    if not ok:
        raise LookupError(f"未找到待更正回执 {target_receipt_id}")

    # 3) 局部路径：只读目标租户分区
    store.reset_access_audit()
    local_receipts = store.read(tenant)
    local_result = detailed_endpoint_result(proposal, local_receipts)
    local_access = set(store.accessed)

    # 4) 全量路径：读所有分区后计算同一端点
    store.reset_access_audit()
    all_receipts = store.read_all()
    full_result = detailed_endpoint_result(proposal, all_receipts)
    full_access = set(store.accessed)

    # 5) 更正后全量语义，找出语义确实变化的租户
    store.reset_access_audit()
    after = tenant_semantic_digest(store, proposals)
    changed_tenants = sorted(
        t for t in set(before) | set(after) if before.get(t) != after.get(t)
    )

    expected_access = {tenant}
    checks = {
        "receipt_replaced": ok,
        "local_access_exact_partition": local_access == expected_access,
        "local_matches_full_result": local_result == full_result,
        "full_scan_accessed_all_partitions": full_access == set(store.tenants()),
        "full_semantic_change_only_target": changed_tenants == [tenant],
    }
    return {
        "checks": checks,
        "all_passed": all(checks.values()),
        "tenant": tenant,
        "endpoint": endpoint,
        "local_access": sorted(local_access),
        "expected_access": sorted(expected_access),
        "full_access_count": len(full_access),
        "changed_tenants_by_full_rescan": changed_tenants,
        "local_result": local_result,
        "full_result": full_result,
        "local_result_digest": result_digest(local_result),
        "target_receipt_id": target_receipt_id,
    }
