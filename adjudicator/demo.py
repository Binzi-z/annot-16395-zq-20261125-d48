"""端到端离线裁决演示与总自检：一条命令核对题面全部硬性要求。

运行：``python solution.py``（或 ``python -m adjudicator.demo``）。
任何一项核对失败，:func:`main` 返回 1，便于接入 CI / 评测。
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any

from .durable import (
    DEFAULT_REQUIRED_RECEIPT,
    FileBarrierLog,
    recover_from_disk,
)
from .engine import (
    brute_force_earliest_tick,
    earliest_actionable_time,
    earliest_by_valid_time,
    evaluate,
    evaluate_known_then,
)
from .exhaustive import (
    check_earliest_bruteforce,
    decision_table,
    enumerate_crash_sequences,
)
from .partitions import audit_local_correction
from .proof import build_veto_proof, verify_proof
from .synth import build_curated, build_shared_root_correction, generate_bulk

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"


def _line(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def _ok(cond: bool, msg: str) -> bool:
    print(f"[{'PASS' if cond else 'FAIL'}] {msg}")
    return cond


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True),
                    encoding="utf-8")


# ---------------------------------------------------------------------------
# 1) 精选双时态剧本 + 最早点 + 否决证明
# ---------------------------------------------------------------------------

def run_curated(report: dict[str, Any]) -> bool:
    _line("1. 双时态裁决 / 最早可恢复点 / 否决证明（精选剧本）")
    cases = build_curated()
    all_ok = True
    proof_chain_prev = "0" * 64
    chain: list[dict[str, str]] = []

    for key, c in cases.items():
        v = evaluate(c["proposal"], c["receipts"])
        got = v["primary_reason"] or "ALLOW"
        expect = c["expect"]
        cond = got == expect
        all_ok &= _ok(cond, f"{key:20s} 结论={got:26s} 期望={expect}")

        early_vt = earliest_by_valid_time(c["proposal"], c["receipts"])["earliest"]
        early_known = earliest_actionable_time(c["proposal"], c["receipts"])["earliest"]
        if "expect_early_vt" in c:
            all_ok &= _ok(early_vt == c["expect_early_vt"],
                          f"    按有效时间最早点={early_vt}（期望 {c['expect_early_vt']}）")
        if "expect_early_action" in c:
            all_ok &= _ok(early_known == c["expect_early_action"],
                          f"    按当时已知重放最早可行动点={early_known}"
                          f"（期望 {c['expect_early_action']}）")

        # 每个否决结论都产出并验证一个可验证否决证明（串成哈希链）。
        if v["decision"] == "DENY":
            proof = build_veto_proof(v, prev_proof_digest=proof_chain_prev)
            vr = verify_proof(proof, expected_prev=proof_chain_prev)
            all_ok &= _ok(vr["ok"], f"    否决证明验证 ok={vr['ok']} "
                                    f"primary={proof['primary_reason']} errors={vr['errors']}")
            proof_chain_prev = proof["proof_digest"]
            chain.append({"case": key, "proof_digest": proof["proof_digest"],
                          "chain_digest": proof["chain_digest"]})
            if key == "same_root":
                _write_json(ART / "sample_veto_proof.json", proof)

    # 双时态核心对照：同一提案在归档当时(40)因回执迟到而否决，60 才满足。
    g = cases["gold_late_in_window"]
    at40 = evaluate_known_then(g["proposal"], g["receipts"], g["archive_at"])
    at60 = evaluate_known_then(g["proposal"], g["receipts"], 60)
    all_ok &= _ok(
        at40["decision"] == "DENY" and at40["primary_reason"] == "E_NOT_TWO_APPROVALS",
        f"归档点 t={g['archive_at']} 按当时已知重放 => {at40['primary_reason']}（迟到回执不可用）",
    )
    all_ok &= _ok(at60["allowed"], "迟到回执到达后 t=60 重放 => ALLOW")

    # 归档后重放：同一 receipt_id 同内容重放被幂等去重，不改变结论。
    iso_receipt = g["receipts"][0]
    replayed = g["receipts"] + [dict(iso_receipt), dict(iso_receipt)]
    v_replay = evaluate(g["proposal"], replayed, at_vt=70)
    all_ok &= _ok(
        v_replay["allowed"] and v_replay["replay"]["identical_replays_deduped"] == 2,
        "归档后相同回执重放 x2 被幂等去重，结论不变",
    )

    # 篡改证明必须被检出。
    sr = evaluate(cases["same_root"]["proposal"], cases["same_root"]["receipts"])
    proof = build_veto_proof(sr)
    tampered = json.loads(json.dumps(proof))
    tampered["primary_reason"] = "E_WINDOW_EXPIRED"
    vt = verify_proof(tampered)
    all_ok &= _ok(not vt["ok"] and any("DIGEST" in e for e in vt["errors"]),
                  "篡改证明 primary_reason 被摘要校验检出")

    report["curated_cases"] = len(cases)
    report["proof_chain_len"] = len(chain)
    report["all_ok"] = all_ok
    return all_ok


# ---------------------------------------------------------------------------
# 2) 最早点边界法 vs 逐 tick 暴力 + 决策表 + 短序列故障穷举
# ---------------------------------------------------------------------------

def run_exhaustive(report: dict[str, Any]) -> bool:
    _line("2. 独立穷举：决策表 / 最早点逐tick对照 / 短序列×全部故障点")
    all_ok = True

    dt = decision_table()
    all_ok &= _ok(dt["passed"],
                  f"决策表全组合 {dt['cases']} 例（其中否决 {dt['denies']}）"
                  f" 与参考合取式完全一致，且否决证明全部可验证")
    if dt["mismatches"]:
        print("    mismatches:", dt["mismatches"][:5])
    if dt["proof_failures"]:
        print("    proof failures:", dt["proof_failures"][:3])

    cases = build_curated()
    eb = check_earliest_bruteforce(cases, horizon=140)
    all_ok &= _ok(eb["passed"],
                  f"最早点候选边界法与逐 tick 暴力预言机一致（{len(eb['rows'])} 个剧本，"
                  f"horizon={eb['horizon']}）")
    for row in eb["rows"]:
        if not row["match"]:
            print("    MISMATCH", row)

    cr = enumerate_crash_sequences(max_len=4, bindings_valid=True)
    all_ok &= _ok(cr["passed"],
                  f"故障穷举：{cr['scripts']} 个短序列 × 各自全部故障点 = "
                  f"{cr['fault_runs']} 次独立崩溃恢复，安全不变量零违反")
    print("    结果分布:", json.dumps(cr["outcome_histogram"], ensure_ascii=False, sort_keys=True))
    rle = cr["revoke_just_landed"]
    all_ok &= _ok(
        rle is not None,
        "定位到『撤销正好落盘』精确故障点 "
        + (f"script={rle['script']} fp=#{rle['fault_point']}({rle['label']}) "
           f"stable={rle['stable_records']} => {rle['outcome']}" if rle else "未找到"),
    )
    rce = cr["receipt_lost_example"]
    all_ok &= _ok(
        rce is not None,
        "定位到『回执已丢但决定已落盘』 "
        + (f"script={rce['script']} fp=#{rce['fault_point']}({rce['label']}) "
           f"staging={rce['stable_staging']} => {rce['outcome']}" if rce else "未找到"),
    )
    if cr["violations"]:
        print("    violations:", cr["violations"][:5])

    # 绑定无效的序列也独立穷举较短长度，确认仍无安全违反。
    cr_bad = enumerate_crash_sequences(max_len=3, bindings_valid=False)
    all_ok &= _ok(cr_bad["safety_passed"],
                  f"绑定无效场景追加穷举：{cr_bad['fault_runs']} 次，零违反"
                  f"（撤销样本={cr_bad['revoke_just_landed'] is not None}）")

    report["decision_table"] = {k: dt[k] for k in ("cases", "denies", "passed")}
    report["crash"] = {
        "scripts": cr["scripts"], "fault_runs": cr["fault_runs"],
        "violation_count": cr["violation_count"], "passed": cr["passed"],
        "outcome_histogram": cr["outcome_histogram"],
        "revoke_just_landed": cr["revoke_just_landed"],
        "receipt_lost_decision_landed": cr["receipt_lost_example"],
        "bad_binding_fault_runs": cr_bad["fault_runs"],
    }
    return all_ok


# ---------------------------------------------------------------------------
# 3) 真实 Windows 文件 + os.fsync 屏障复测两个题名结果
# ---------------------------------------------------------------------------

def run_file_barrier_demo(report: dict[str, Any]) -> bool:
    _line("3. 真实文件 fsync 屏障复测（artifacts/durable_demo，可在 Windows 重开核对）")
    base = ART / "durable_demo"
    shutil.rmtree(base, ignore_errors=True)
    all_ok = True

    # 场景 A：INTENT 落盘 -> REVOKE 写入并 barrier(fsync) 正好落盘 -> 崩溃。
    da = base / "revoke_landed"
    s = FileBarrierLog(da / "staging.jsonl")
    q = FileBarrierLog(da / "receipts.jsonl")
    s.append({"rec": "INTENT", "proposal_id": "P-FILE-A",
              "bound_digest": "x", "required_receipt": DEFAULT_REQUIRED_RECEIPT})
    s.barrier()
    s.append({"rec": "REVOKE", "target_digest": "x", "source": "remote-cancel"})
    s.barrier()  # <<< 撤销正好越过 fsync 屏障
    s.crash()
    q.crash()
    ra = recover_from_disk(da / "staging.jsonl", da / "receipts.jsonl")
    all_ok &= _ok(ra["outcome"] == "REVOKED",
                  f"A 撤销已 fsync 落盘，重开文件恢复 => {ra['outcome']}（stable={[r['rec'] for r in ra['stable_staging']]}）")

    # 场景 B：DECISION(APPROVE) barrier 落盘；回执仅 append 未 barrier 即崩溃丢失。
    db = base / "receipt_lost_decision_landed"
    s = FileBarrierLog(db / "staging.jsonl")
    q = FileBarrierLog(db / "receipts.jsonl")
    s.append({"rec": "INTENT", "proposal_id": "P-FILE-B",
              "bound_digest": "y", "required_receipt": DEFAULT_REQUIRED_RECEIPT})
    s.barrier()
    s.append({"rec": "DECISION", "verdict": "APPROVE", "reason": None})
    s.barrier()  # <<< 决定已 fsync 落盘
    q.append({"rec": "RECEIPT", "receipt_id": DEFAULT_REQUIRED_RECEIPT, "ok": True})
    # 故意不调用 q.barrier()：故障点位于 receipt.post_append。
    s.crash()
    q.crash()
    rb = recover_from_disk(db / "staging.jsonl", db / "receipts.jsonl",
                           DEFAULT_REQUIRED_RECEIPT)
    all_ok &= _ok(rb["outcome"] == "DECISION_STANDS_RECEIPT_GAP",
                  f"B 回执未越屏障而丢、决定已 fsync，重开恢复 => {rb['outcome']} "
                  f"durable_verdict={rb['durable_verdict']} gap={rb['receipt_gap']}")

    # 半行撕裂容错：在已 fsync 日志尾部追加不完整 JSON 行，应被忽略而不影响既有记录。
    torn = base / "torn.jsonl"
    tl = FileBarrierLog(torn)
    tl.append({"rec": "DECISION", "verdict": "DENY", "reason": "E_REVOKED"})
    tl.barrier()
    tl.close()
    with open(torn, "a", encoding="utf-8") as fh:
        fh.write('{"rec":"DECISIO')  # 崩溃在写行中间，无换行的半行
    recs = FileBarrierLog.read_disk(torn)
    all_ok &= _ok(len(recs) == 1 and recs[0]["verdict"] == "DENY",
                  "日志尾部撕裂半行被安全忽略，已落盘完整记录仍可恢复")

    report["file_barrier"] = {"A": ra["outcome"], "B": rb["outcome"],
                              "torn_lines_parsed": len(recs)}
    return all_ok


# ---------------------------------------------------------------------------
# 4) 6 万+分租户回执：全量裁决 + 局部更正访问分区核对
# ---------------------------------------------------------------------------

def run_scale_and_partitions(report: dict[str, Any]) -> bool:
    _line("4. >=60000 条分租户回执：全量核对 + 局部更正访问分区 vs 全量")
    bulk = generate_bulk()
    store = bulk["store"]
    proposals = bulk["proposals"]
    expected = bulk["expected"]
    total = bulk["total_receipts"]

    counts = store.partition_counts()
    print(f"生成回执总数={total}，租户数={len(counts)}，每租户={bulk['endpoints_per_tenant']*8}")
    print("各租户分区条数:", json.dumps(counts, ensure_ascii=False, sort_keys=True))

    # 全量扫描一次并按端点分组（真实“全量”路径）。
    all_receipts = store.read_all()
    grouped: dict[tuple[str, str], list[dict]] = {}
    for r in all_receipts:
        grouped.setdefault((r["tenant_id"], r["endpoint_id"]), []).append(r)

    mismatches = []
    for p in proposals:
        key = (p["tenant_id"], p["endpoint_id"])
        v = evaluate(p, grouped[key], at_vt=p["at_vt"])
        got = v["primary_reason"] or "ALLOW"
        if got != expected[key]:
            mismatches.append({"key": key, "got": got, "expected": expected[key]})
    sweep_ok = not mismatches and total >= 60000
    print(f"[{'PASS' if sweep_ok else 'FAIL'}] 全量 {len(proposals)} 个端点裁决与合成期望一致；"
          f"回执 {total} >= 60000；不一致 {len(mismatches)}")
    if mismatches[:5]:
        print("   ", mismatches[:5])

    # 局部更正：把 t00/EP-0-00000 的第二独立批准改成同根，期望翻成 SHARED_ROOT。
    sample = bulk["correction_sample"]
    corrected = build_shared_root_correction(store, sample)
    target_proposal = next(
        p for p in proposals
        if p["tenant_id"] == sample["tenant"] and p["endpoint_id"] == sample["endpoint"]
    )
    audit = audit_local_correction(
        store, proposals,
        tenant=sample["tenant"], endpoint=sample["endpoint"],
        proposal=target_proposal,
        target_receipt_id=sample["target_receipt_id"],
        corrected_receipt=corrected,
    )
    print("局部更正核对明细:")
    for k, val in audit["checks"].items():
        print(f"   [{'PASS' if val else 'FAIL'}] {k}")
    print("   局部实际访问分区:", audit["local_access"],
          " 全量重扫语义变化租户:", audit["changed_tenants_by_full_rescan"])
    print("   局部结果:", json.dumps(audit["local_result"], ensure_ascii=False, sort_keys=True))

    corr_ok = audit["all_passed"]
    overall = sweep_ok and corr_ok
    report["scale"] = {
        "total_receipts": total,
        "tenants": len(counts),
        "endpoints": len(proposals),
        "expected_distribution": bulk["counts_by_expect"],
        "full_sweep_mismatches": len(mismatches),
        "correction_audit": {
            "all_passed": audit["all_passed"],
            "checks": audit["checks"],
            "local_access": audit["local_access"],
            "changed_tenants": audit["changed_tenants_by_full_rescan"],
            "after_decision": audit["local_result"]["decision"],
            "after_primary_reason": audit["local_result"]["primary_reason"],
        },
    }
    return overall


# ---------------------------------------------------------------------------

def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    ART.mkdir(exist_ok=True)
    report: dict[str, Any] = {"schema": "drill-16395-report/v1"}
    results = [
        run_curated(report),
        run_exhaustive(report),
        run_file_barrier_demo(report),
        run_scale_and_partitions(report),
    ]
    report["overall_pass"] = all(results)
    _write_json(ART / "demo_report.json", report)

    _line("总结")
    for i, r in enumerate(results, 1):
        print(f"  模块 {i}: {'PASS' if r else 'FAIL'}")
    print(f"\n总体: {'ALL CHECKS PASSED' if report['overall_pass'] else 'HAS FAILURES'}")
    print(f"机器可读报告: {ART / 'demo_report.json'}")
    print(f"样例否决证明: {ART / 'sample_veto_proof.json'}")
    return 0 if report["overall_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
