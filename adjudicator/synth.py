"""确定性本地合成数据：精选双时态剧本 + >=60000 条分租户回执。

不使用墙钟/真随机源的不可复现部分：固定种子 ``20261125``，保证任何机器、
任何时候生成的数据完全一致，便于离线复核与回归。
"""

from __future__ import annotations

import copy
import random
from typing import Any

from .model import (
    make_approval,
    make_extend,
    make_isolate,
    make_proposal,
    make_receipt,
    make_revoke,
    make_rotation,
    event_digest,
)
from .partitions import PartitionedStore

SEED = 20261125
CURATED_TENANT = "t-cur"

REASON_ALLOW = "ALLOW"


# ---------------------------------------------------------------------------
# 精选剧本（驱动双时态差异、最早点与否决证明）
# ---------------------------------------------------------------------------

def _curated_case(key: str, title: str, recs, proposal, expect, **extra):
    return {
        "key": key,
        "title": title,
        "tenant": CURATED_TENANT,
        "receipts": recs,
        "proposal": proposal,
        "expect": expect,
        **extra,
    }


def build_curated() -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}

    # ---- 1) 迟到但仍在窗口内：有效时间最早=12，实际可知最早=60 ----------
    ep = "EP-GOLD"
    iso = make_isolate(CURATED_TENANT, ep, 10, 10, 100)
    d = event_digest(iso)
    recs = [make_receipt("C-GOLD-ISO", 11, iso)]
    ext = make_extend(CURATED_TENANT, ep, 15, d, 10, 110, parent_digest=d)
    recs.append(make_receipt("C-GOLD-EXT", 16, ext))
    a = make_approval("A-GOLD-1", CURATED_TENANT, ep, 11, "alice",
                      ["alice", "rootR1"], 1, 10, 100)
    b = make_approval("A-GOLD-2", CURATED_TENANT, ep, 12, "bob",
                      ["bob", "ctrlX", "rootR2"], 1, 12, 100)
    recs.append(make_receipt("C-GOLD-AP1", 12, a))
    recs.append(make_receipt("C-GOLD-AP2-LATE", 60, b))  # 异地回执迟到，归档点=40
    p = make_proposal("P-GOLD", CURATED_TENANT, ep, 70, d, 1,
                      ["A-GOLD-1", "A-GOLD-2"])
    cases["gold_late_in_window"] = _curated_case(
        "gold_late_in_window",
        "第二独立批准迟到但窗口未关：有效时间可追溯到12，实际60才可恢复",
        recs, p, REASON_ALLOW,
        archive_at=40, expect_early_vt=12, expect_early_action=60,
    )

    # ---- 2) 迟到且窗口已过：有效时间12曾可恢复，实际永远错过 -------------
    ep = "EP-LATE-EXPIRE"
    iso = make_isolate(CURATED_TENANT, ep, 10, 10, 50)
    d = event_digest(iso)
    recs = [make_receipt("C-EXP-ISO", 11, iso)]
    a = make_approval("A-EXP-1", CURATED_TENANT, ep, 11, "ann",
                      ["ann", "rootE1"], 1, 10, 200)
    b = make_approval("A-EXP-2", CURATED_TENANT, ep, 12, "ben",
                      ["ben", "rootE2"], 1, 12, 200)
    recs.append(make_receipt("C-EXP-AP1", 12, a))
    recs.append(make_receipt("C-EXP-AP2-LATE", 80, b))  # 到达时窗口(末=50)已过
    p = make_proposal("P-EXP", CURATED_TENANT, ep, 80, d, 1,
                      ["A-EXP-1", "A-EXP-2"])
    cases["late_expired"] = _curated_case(
        "late_expired",
        "关键批准迟到至窗口关闭后：有效时间回看12可恢复，当时重放最终被窗口否决",
        recs, p, "E_WINDOW_EXPIRED",
        expect_early_vt=12, expect_early_action=None,
    )

    # ---- 3) 两个批准同一根控制人 -----------------------------------------
    ep = "EP-SAMEROOT"
    iso = make_isolate(CURATED_TENANT, ep, 10, 10, 200)
    d = event_digest(iso)
    recs = [make_receipt("C-SR-ISO", 11, iso)]
    a1 = make_approval("A-SR-1", CURATED_TENANT, ep, 12, "u1",
                       ["u1", "rootShared"], 1, 10, 200)
    a2 = make_approval("A-SR-2", CURATED_TENANT, ep, 12, "u2",
                       ["u2", "mgr", "rootShared"], 1, 10, 200)
    recs += [make_receipt("C-SR-AP1", 13, a1), make_receipt("C-SR-AP2", 13, a2)]
    p = make_proposal("P-SR", CURATED_TENANT, ep, 30, d, 1, ["A-SR-1", "A-SR-2"])
    cases["same_root"] = _curated_case(
        "same_root", "两个不同批准人但同根控制人 => 不满足独立批准",
        recs, p, "E_SHARED_ROOT",
    )

    # ---- 4) 授权代已轮换，提案仍绑旧代 -----------------------------------
    ep = "EP-STALEGEN"
    iso = make_isolate(CURATED_TENANT, ep, 5, 5, 220)
    d = event_digest(iso)
    recs = [make_receipt("C-GEN-ISO", 6, iso)]
    rot = make_rotation(CURATED_TENANT, ep, 20, 2)
    recs.append(make_receipt("C-GEN-ROT", 21, rot))
    a = make_approval("A-GEN-1", CURATED_TENANT, ep, 22, "ira",
                      ["ira", "rootG1"], 2, 22, 200)
    b = make_approval("A-GEN-2", CURATED_TENANT, ep, 22, "ivy",
                      ["ivy", "rootG2"], 2, 22, 200)
    recs += [make_receipt("C-GEN-AP1", 23, a), make_receipt("C-GEN-AP2", 23, b)]
    p = make_proposal("P-GEN", CURATED_TENANT, ep, 30, d, 1, ["A-GEN-1", "A-GEN-2"])
    cases["stale_gen"] = _curated_case(
        "stale_gen", "授权代已从1轮换到2，提案仍绑定第1代 => 否决",
        recs, p, "E_AUTH_GENERATION_STALE",
    )

    # ---- 5) 绑定了错误的原隔离摘要 ---------------------------------------
    ep = "EP-DIGEST"
    iso = make_isolate(CURATED_TENANT, ep, 10, 10, 200)
    d = event_digest(iso)  # noqa: F841 (真实摘要是 d，提案故意绑错)
    recs = [make_receipt("C-DG-ISO", 11, iso)]
    a = make_approval("A-DG-1", CURATED_TENANT, ep, 12, "pa",
                      ["pa", "rootD1"], 1, 10, 200)
    b = make_approval("A-DG-2", CURATED_TENANT, ep, 12, "qb",
                      ["qb", "rootD2"], 1, 10, 200)
    recs += [make_receipt("C-DG-AP1", 13, a), make_receipt("C-DG-AP2", 13, b)]
    p = make_proposal("P-DG", CURATED_TENANT, ep, 30, "0" * 64, 1,
                      ["A-DG-1", "A-DG-2"])
    cases["digest_mismatch"] = _curated_case(
        "digest_mismatch", "恢复提案绑定的摘要不等于原隔离事件摘要 => 否决",
        recs, p, "E_DIGEST_MISMATCH", real_digest=d,
    )

    # ---- 6) 已落盘撤销 ----------------------------------------------------
    ep = "EP-REVOKE"
    iso = make_isolate(CURATED_TENANT, ep, 10, 10, 200)
    d = event_digest(iso)
    recs = [make_receipt("C-RV-ISO", 11, iso)]
    a = make_approval("A-RV-1", CURATED_TENANT, ep, 12, "ra1",
                      ["ra1", "rootV1"], 1, 10, 200)
    b = make_approval("A-RV-2", CURATED_TENANT, ep, 12, "rb2",
                      ["rb2", "rootV2"], 1, 10, 200)
    recs += [make_receipt("C-RV-AP1", 13, a), make_receipt("C-RV-AP2", 13, b)]
    rv = make_revoke(CURATED_TENANT, ep, 25, d)
    recs.append(make_receipt("C-RV-NOTICE", 26, rv))
    p = make_proposal("P-RV", CURATED_TENANT, ep, 30, d, 1, ["A-RV-1", "A-RV-2"])
    cases["revoked"] = _curated_case(
        "revoked", "所有绑定齐备，但存在已生效撤销 => 否决",
        recs, p, "E_REVOKED",
    )

    # ---- 7) 只有一个可用批准 ---------------------------------------------
    ep = "EP-NOTWO"
    iso = make_isolate(CURATED_TENANT, ep, 10, 10, 200)
    d = event_digest(iso)
    recs = [make_receipt("C-N2-ISO", 11, iso)]
    a = make_approval("A-N2-1", CURATED_TENANT, ep, 12, "solo",
                      ["solo", "rootSolo"], 1, 10, 200)
    recs.append(make_receipt("C-N2-AP1", 13, a))
    p = make_proposal("P-N2", CURATED_TENANT, ep, 30, d, 1,
                      ["A-N2-1", "A-N2-MISSING"])
    cases["not_two"] = _curated_case(
        "not_two", "只有一个可用批准（第二个不存在）=> E_NOT_TWO_APPROVALS",
        recs, p, "E_NOT_TWO_APPROVALS",
    )

    return cases


# ---------------------------------------------------------------------------
# 大规模分租户数据
# ---------------------------------------------------------------------------

def _ack(tenant: str, ep: str, idx: int, vt: int) -> dict[str, Any]:
    return {
        "kind": "DELIVERY_ACK",
        "tenant_id": tenant,
        "endpoint_id": ep,
        "vt": vt,
        "ack_seq": idx,
    }


def generate_bulk(
    *,
    n_tenants: int = 8,
    endpoints_per_tenant: int = 1000,
    pad_to: int = 8,
    seed: int = SEED,
) -> dict[str, Any]:
    """生成 exactly ``n_tenants*endpoints_per_tenant*pad_to`` 条唯一回执。

    默认 8*1000*8 = 64000 >= 60000。每个端点是一个完整小剧本并带已知期望结论，
    因此全量扫描同时是一次 8000 用例的端到端核对。
    """
    rng = random.Random(seed)
    store = PartitionedStore()
    proposals: list[dict[str, Any]] = []
    expected: dict[tuple[str, str], str] = {}
    counts: dict[str, int] = {}
    correction_sample: dict[str, Any] | None = None

    for ti in range(n_tenants):
        tenant = f"t{ti:02d}"
        for ei in range(endpoints_per_tenant):
            ep = f"EP-{ti}-{ei:05d}"
            residue = ei % 20
            if residue < 14:
                kind = "ALLOW"
            elif residue in (14, 15):
                kind = "E_SHARED_ROOT"
            elif residue == 16:
                kind = "E_AUTH_GENERATION_STALE"
            elif residue == 17:
                kind = "E_WINDOW_EXPIRED"
            elif residue == 18:
                kind = "E_DIGEST_MISMATCH"
            else:
                kind = "E_REVOKED"
            counts[kind] = counts.get(kind, 0) + 1

            recs: list[dict[str, Any]] = []
            serial = [0]

            def add(fact: dict[str, Any], rt: int | None = None, tag: str | None = None):
                serial[0] += 1
                suffix = tag or f"F{serial[0]}"
                rid = f"R-{ti:02d}-{ei:05d}-{suffix}"
                receipt = make_receipt(rid, fact["vt"] + 1 if rt is None else rt, fact)
                recs.append(receipt)
                return receipt

            iso = make_isolate(tenant, ep, 10, 10, 200)
            diso = event_digest(iso)
            add(iso, tag="ISO")

            bound_digest = diso
            prop_gen = 1
            at_vt = 30
            appr_ids = ["AP1", "AP2"]

            if kind == "ALLOW":
                add(make_extend(tenant, ep, 15, diso, 10, 220, parent_digest=diso),
                    tag="EXT")
                a = make_approval("AP1", tenant, ep, 12, f"u{ei}a",
                                  [f"u{ei}a", f"root-a-{ti}"], 1, 10, 200)
                b = make_approval("AP2", tenant, ep, 12, f"u{ei}b",
                                  [f"u{ei}b", f"root-b-{ti}"], 1, 10, 200)
                add(a, tag="AP1")
                r_b = add(b, tag="AP2")
                if correction_sample is None and ti == 0 and ei == 0:
                    correction_sample = {
                        "tenant": tenant,
                        "endpoint": ep,
                        "target_receipt_id": r_b["receipt_id"],
                        "flip_to_root": f"root-a-{ti}",
                    }

            elif kind == "E_SHARED_ROOT":
                root = f"root-shared-{ti}"
                a = make_approval("AP1", tenant, ep, 12, f"u{ei}1",
                                  [f"u{ei}1", root], 1, 10, 200)
                b = make_approval("AP2", tenant, ep, 12, f"u{ei}2",
                                  [f"u{ei}2", "mgr", root], 1, 10, 200)
                add(a, tag="AP1")
                add(b, tag="AP2")

            elif kind == "E_AUTH_GENERATION_STALE":
                add(make_rotation(tenant, ep, 20, 2), tag="ROT")
                a = make_approval("AP1", tenant, ep, 22, f"g{ei}a",
                                  [f"g{ei}a", f"root-ga-{ti}"], 2, 22, 200)
                b = make_approval("AP2", tenant, ep, 22, f"g{ei}b",
                                  [f"g{ei}b", f"root-gb-{ti}"], 2, 22, 200)
                add(a, tag="AP1")
                add(b, tag="AP2")
                prop_gen = 1

            elif kind == "E_WINDOW_EXPIRED":
                iso2 = make_isolate(tenant, ep, 10, 10, 40)
                # 用 40 秒窗口的隔离替换先前默认隔离，保持“原隔离唯一”。
                recs.clear()
                serial[0] = 0
                diso = event_digest(iso2)
                bound_digest = diso  # 提案必须绑定新的原隔离，才能走到窗口原因
                add(iso2, tag="ISO")
                a = make_approval("AP1", tenant, ep, 12, f"w{ei}a",
                                  [f"w{ei}a", f"root-wa-{ti}"], 1, 10, 200)
                b = make_approval("AP2", tenant, ep, 12, f"w{ei}b",
                                  [f"w{ei}b", f"root-wb-{ti}"], 1, 10, 200)
                add(a, tag="AP1")
                add(b, tag="AP2")
                at_vt = 60

            elif kind == "E_DIGEST_MISMATCH":
                bound_digest = "0" * 64
                a = make_approval("AP1", tenant, ep, 12, f"d{ei}a",
                                  [f"d{ei}a", f"root-da-{ti}"], 1, 10, 200)
                b = make_approval("AP2", tenant, ep, 12, f"d{ei}b",
                                  [f"d{ei}b", f"root-db-{ti}"], 1, 10, 200)
                add(a, tag="AP1")
                add(b, tag="AP2")

            else:  # E_REVOKED
                a = make_approval("AP1", tenant, ep, 12, f"v{ei}a",
                                  [f"v{ei}a", f"root-va-{ti}"], 1, 10, 200)
                b = make_approval("AP2", tenant, ep, 12, f"v{ei}b",
                                  [f"v{ei}b", f"root-vb-{ti}"], 1, 10, 200)
                add(a, tag="AP1")
                add(b, tag="AP2")
                add(make_revoke(tenant, ep, 25, diso), tag="RV")

            # 补足到固定回执数（异地投递确认/心跳），保证总量 >= 60000。
            ack_i = 0
            while len(recs) < pad_to:
                ack_i += 1
                add(_ack(tenant, ep, ack_i, 14 + ack_i), rt=15 + ack_i,
                    tag=f"ACK{ack_i}")

            for r in recs:
                store.add(r)

            proposal = make_proposal(
                f"P-{ti:02d}-{ei:05d}", tenant, ep, at_vt,
                bound_digest, prop_gen, appr_ids,
            )
            proposals.append(proposal)
            expected[(tenant, ep)] = kind

    total = store.size()
    assert total >= 60000, f"合成回执仅 {total} 条，未达 60000"
    assert correction_sample is not None

    return {
        "store": store,
        "proposals": proposals,
        "expected": expected,
        "counts_by_expect": counts,
        "correction_sample": correction_sample,
        "total_receipts": total,
        "n_tenants": n_tenants,
        "endpoints_per_tenant": endpoints_per_tenant,
    }


def build_shared_root_correction(store: PartitionedStore, sample: dict) -> dict:
    """基于样本构造一份“把第二批准改成与第一批准同根”的更正后回执。"""
    tenant = sample["tenant"]
    rid = sample["target_receipt_id"]
    original = next(r for r in store.read(tenant) if r["receipt_id"] == rid)
    corrected = copy.deepcopy(original)
    new_fact = copy.deepcopy(corrected["fact"])
    approver = new_fact["approver"]
    new_root = sample["flip_to_root"]
    new_fact["control_chain"] = [approver, new_root]
    new_fact["root_controller"] = new_root
    corrected["fact"] = new_fact
    corrected["event_digest"] = event_digest(new_fact)  # 行政更正后重算摘要
    corrected["correction_of"] = rid
    return corrected
