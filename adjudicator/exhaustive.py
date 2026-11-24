"""独立穷举复核。

三块相互独立的穷举/预言机：

1. :func:`decision_table` —— 对五项必要条件的因子做全组合（144 例），
   用一个 *参考合取式* 独立给出 ALLOW/DENY，与引擎逐一比对；每个否决结论
   都构造并验证否决证明。

2. :func:`check_earliest_bruteforce` —— 对精选剧本，用逐 tick 暴力扫描作为
   独立预言机，核对候选边界法得到的“有效时间最早点 / 实际可知最早点”。

3. :func:`enumerate_crash_sequences` —— 枚举长度 1..max_len 的全部短操作序列，
   对每个序列独立扫过 *每一个故障点*，崩溃后恢复，并用直接读 stable 原始记录
   的安全预言机核对不变量 I1–I5。同时定位两个题名边界结果的精确坐标。
"""

from __future__ import annotations

import itertools
from typing import Any

from .durable import (
    ALPHABET,
    OP_DECIDE,
    OP_RECEIPT,
    OP_REVOKE,
    Crash,
    DurableWorld,
    FaultInjector,
    StagingActor,
    classify_stable,
    recover_world,
)
from .engine import (
    brute_force_earliest_tick,
    earliest_actionable_time,
    earliest_by_valid_time,
    evaluate,
)
from .model import make_approval, make_isolate, make_proposal, make_receipt, make_revoke, event_digest
from .proof import build_veto_proof, verify_proof


# ---------------------------------------------------------------------------
# 1) 决策表全组合
# ---------------------------------------------------------------------------

def _factor_case(digest_ok, n_appr, same_root, gen_ok, window, revoked):
    tenant, ep = "t-dt", "EP-DT"
    t = 50
    if window == "open":
        ws, we = 10, 100
    elif window == "expired":
        ws, we = 10, 40
    else:  # future
        ws, we = 60, 200
    iso = make_isolate(tenant, ep, 10, ws, we)
    d = event_digest(iso)
    receipts = [make_receipt("ISO", 11, iso)]

    ids: list[str] = []
    for i in range(n_appr):
        aid = f"AP{i}"
        ids.append(aid)
        root = "rootSame" if same_root else f"rootDistinct{i}"
        a = make_approval(aid, tenant, ep, 12, f"user{i}",
                          [f"user{i}", root], 1, 10, 200)
        receipts.append(make_receipt(f"R-{aid}", 13, a))

    if revoked:
        receipts.append(make_receipt("RV", 20, make_revoke(tenant, ep, 20, d)))

    bound = d if digest_ok else "1" * 64
    proposal = make_proposal("P-DT", tenant, ep, t, bound, 1 if gen_ok else 9, ids)

    reference_allow = (
        digest_ok
        and n_appr >= 2
        and (not same_root)
        and gen_ok
        and window == "open"
        and (not revoked)
    )
    return proposal, receipts, reference_allow


def decision_table() -> dict[str, Any]:
    factors = list(itertools.product(
        [True, False],          # digest_ok
        [0, 1, 2],              # n_approvals
        [True, False],          # same_root
        [True, False],          # gen_ok
        ["open", "expired", "future"],
        [True, False],          # revoked
    ))
    mismatches: list[dict] = []
    proof_failures: list[dict] = []
    denies = 0

    for combo in factors:
        proposal, receipts, ref_allow = _factor_case(*combo)
        v = evaluate(proposal, receipts)
        if v["allowed"] != ref_allow:
            mismatches.append({
                "factors": combo,
                "reference_allow": ref_allow,
                "engine_allow": v["allowed"],
                "primary": v["primary_reason"],
            })
        if v["decision"] == "DENY":
            denies += 1
            proof = build_veto_proof(v)
            vr = verify_proof(proof)
            if not vr["ok"]:
                proof_failures.append({"factors": combo, "errors": vr["errors"]})

    return {
        "cases": len(factors),
        "denies": denies,
        "mismatches": mismatches,
        "proof_failures": proof_failures,
        "passed": not mismatches and not proof_failures,
    }


# ---------------------------------------------------------------------------
# 2) 最早点 vs 逐 tick 暴力预言机
# ---------------------------------------------------------------------------

def check_earliest_bruteforce(cases: dict[str, dict], horizon: int = 140) -> dict[str, Any]:
    rows = []
    failures = []
    for key, case in cases.items():
        p, rs = case["proposal"], case["receipts"]
        cand_v = earliest_by_valid_time(p, rs)["earliest"]
        cand_k = earliest_actionable_time(p, rs)["earliest"]
        brute_v = brute_force_earliest_tick(p, rs, horizon, known_then=False)
        brute_k = brute_force_earliest_tick(p, rs, horizon, known_then=True)
        ok_v = cand_v == brute_v
        ok_k = cand_k == brute_k
        rows.append({
            "case": key,
            "candidate_valid_time": cand_v,
            "bruteforce_valid_time": brute_v,
            "candidate_actionable": cand_k,
            "bruteforce_actionable": brute_k,
            "match": ok_v and ok_k,
        })
        if not (ok_v and ok_k):
            failures.append(rows[-1])
    return {"horizon": horizon, "rows": rows, "failures": failures,
            "passed": not failures}


# ---------------------------------------------------------------------------
# 3) 短序列 x 全部故障点
# ---------------------------------------------------------------------------

def _raw_receipt_ids(world: DurableWorld) -> set[str]:
    return {r.get("receipt_id") for r in world.receipts.stable if r.get("rec") == "RECEIPT"}


def safety_violations(world: DurableWorld, out: dict[str, Any]) -> list[str]:
    """直接读 stable 原始记录的独立安全预言机（不复用 classify 的结论）。"""
    recs = list(world.staging.stable)
    rids = _raw_receipt_ids(world)
    required = world.required_receipt
    viol: list[str] = []

    applied_is = [i for i, r in enumerate(recs) if r["rec"] == "APPLIED"]
    revoke_is = [i for i, r in enumerate(recs) if r["rec"] == "REVOKE"]

    legal_applied_any = False
    for ai in applied_is:
        approve_before = any(
            j < ai and recs[j]["rec"] == "DECISION" and recs[j].get("verdict") == "APPROVE"
            for j in range(ai)
        )
        revoke_before = any(j < ai for j in revoke_is)
        if not approve_before:
            viol.append("APPLIED_WITHOUT_PRIOR_APPROVE_DECISION")
        if revoke_before:
            viol.append("APPLIED_AFTER_DURABLE_REVOKE")
        if approve_before and not revoke_before:
            legal_applied_any = True

    if out.get("restored_effective") and not applied_is:
        viol.append("OUTCOME_CLAIMS_RESTORED_BUT_NO_APPLIED_RECORD")
    if out["outcome"] == "RESTORED" and not legal_applied_any:
        viol.append("OUTCOME_RESTORED_WITHOUT_LEGAL_APPLIED")

    if revoke_is and not legal_applied_any:
        if out["outcome"] != "REVOKED":
            viol.append(f"DURABLE_REVOKE_BUT_OUTCOME_{out['outcome']}")

    if out["outcome"] == "REVOKED" and not revoke_is:
        viol.append("OUTCOME_REVOKED_BUT_NO_REVOKE_RECORD")

    if out["outcome"] == "DECISION_STANDS_RECEIPT_GAP":
        has_approve = any(
            r["rec"] == "DECISION" and r.get("verdict") == "APPROVE" for r in recs
        )
        if not has_approve:
            viol.append("GAP_OUTCOME_WITHOUT_APPROVE_DECISION")
        if required in rids:
            viol.append("GAP_OUTCOME_BUT_REQUIRED_RECEIPT_IS_STABLE")

    # I5 确定性：同一 stable 输入分类两次必须完全一致（去掉易变键后比较）。
    again = classify_stable(list(recs), set(rids), required)
    for k in ("outcome", "restored_effective", "receipt_gap", "decision_immutable"):
        if again.get(k) != out.get(k):
            viol.append("NON_DETERMINISTIC_CLASSIFICATION")
            break

    return viol


def enumerate_crash_sequences(max_len: int = 4, *, bindings_valid: bool = True) -> dict[str, Any]:
    scripts: list[tuple[str, ...]] = []
    for length in range(1, max_len + 1):
        scripts.extend(itertools.product(ALPHABET, repeat=length))

    total_runs = 0
    all_violations: list[dict[str, Any]] = []
    outcome_hist: dict[str, int] = {}
    revoke_landed_example: dict[str, Any] | None = None
    receipt_lost_example: dict[str, Any] | None = None

    for script in scripts:
        # 先无崩溃跑一遍，确定该脚本的故障点总数 N（前缀状态确定，索引可复现）。
        clean = DurableWorld()
        clean_inj = FaultInjector(crash_at=None)
        StagingActor(clean, clean_inj, bindings_valid=bindings_valid).run_script(script)
        n_points = clean_inj.seen

        for fp in range(n_points):
            total_runs += 1
            world = DurableWorld()
            inj = FaultInjector(crash_at=fp)
            actor = StagingActor(world, inj, bindings_valid=bindings_valid)
            crashed_label = None
            try:
                actor.run_script(script)
            except Crash as c:
                crashed_label = c.label

            out = recover_world(world)
            outcome_hist[out["outcome"]] = outcome_hist.get(out["outcome"], 0) + 1

            v = safety_violations(world, out)
            if v:
                all_violations.append({
                    "script": list(script), "fault_point": fp, "label": crashed_label,
                    "outcome": out["outcome"], "violations": v,
                })

            # 记录两个题名边界结果的最精确坐标。
            stable_rec_names = [r["rec"] for r in world.staging.stable]
            is_revoke_landed = (
                crashed_label == "revoke.post_barrier"
                and out["outcome"] == "REVOKED"
            )
            # 优先保留带 INTENT 的“恢复暂存中”样本；否则保留任一命中。
            if is_revoke_landed and (
                revoke_landed_example is None
                or (
                    "INTENT" in stable_rec_names
                    and "INTENT" not in revoke_landed_example["stable_records"]
                )
            ):
                revoke_landed_example = {
                    "script": list(script), "fault_point": fp, "label": crashed_label,
                    "outcome": out["outcome"],
                    "stable_records": stable_rec_names,
                }
            if (
                crashed_label == f"{OP_RECEIPT}.post_append"
                and out["outcome"] == "DECISION_STANDS_RECEIPT_GAP"
            ):
                # 优先保留“回执 append 后、barrier 前崩溃”这一最贴切样本。
                receipt_lost_example = {
                    "script": list(script), "fault_point": fp, "label": crashed_label,
                    "outcome": out["outcome"],
                    "stable_staging": [r["rec"] for r in world.staging.stable],
                    "stable_receipt_ids": out["stable_receipt_ids"],
                }

    safety_passed = not all_violations
    examples_complete = (
        revoke_landed_example is not None
        and receipt_lost_example is not None
    )
    return {
        "alphabet": list(ALPHABET),
        "max_len": max_len,
        "scripts": len(scripts),
        "fault_runs": total_runs,
        "outcome_histogram": outcome_hist,
        "violations": all_violations[:20],
        "violation_count": len(all_violations),
        "revoke_just_landed": revoke_landed_example,
        "receipt_lost_decision_landed": receipt_lost_example,
        "safety_passed": safety_passed,
        "examples_complete": examples_complete,
        # 主有效绑定场景：既无安全违反，也要定位到两个题名边界样本。
        "passed": safety_passed and examples_complete,
    }
