"""离线裁决器的独立测试套件（标准库 unittest）。

运行：
    python -m unittest -v test_adjudicator
或：
    python test_adjudicator.py

覆盖：根控制人独立性、四项绑定、双时态差异、最早点逐 tick 对照、
否决证明验证与篡改/逻辑撒谎检出、屏障故障点两个题名结果、短序列穷举、
真实 fsync 文件恢复、64000 回执全量一致、局部更正访问分区精确一致。
"""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from adjudicator.durable import (
    ALPHABET,
    Crash,
    DurableWorld,
    FaultInjector,
    FileBarrierLog,
    StagingActor,
    recover_from_disk,
    recover_world,
)
from adjudicator.engine import (
    brute_force_earliest_tick,
    earliest_actionable_time,
    earliest_by_valid_time,
    evaluate,
    evaluate_known_then,
)
from adjudicator.exhaustive import (
    check_earliest_bruteforce,
    decision_table,
    enumerate_crash_sequences,
)
from adjudicator.hashing import merkle_root, sha256_hex
from adjudicator.partitions import audit_local_correction
from adjudicator.proof import (
    DEMO_SIGNING_KEY,
    build_veto_proof,
    finalize_proof,
    verify_proof,
)
from adjudicator.roots import RootResolver
from adjudicator.synth import (
    build_curated,
    build_shared_root_correction,
    generate_bulk,
)


def fault_index_for(script, label):
    inj = FaultInjector()
    StagingActor(DurableWorld(), inj).run_script(script)
    return inj.labels.index(label)


class RootIndependenceTests(unittest.TestCase):
    def test_resolver_follows_forest_and_detects_cycle(self):
        r = RootResolver({"a": "m", "m": "rootX", "b": "rootY"})
        self.assertEqual(r.root_of("a"), "rootX")
        self.assertEqual(r.root_of("m"), "rootX")
        self.assertEqual(r.root_of("b"), "rootY")
        cyc = RootResolver({"x": "y", "y": "x"})
        with self.assertRaises(Exception):
            cyc.root_of("x")

    def test_same_root_is_not_independent_even_with_distinct_approvers(self):
        cases = build_curated()
        v = evaluate(cases["same_root"]["proposal"], cases["same_root"]["receipts"])
        self.assertFalse(v["allowed"])
        self.assertEqual(v["primary_reason"], "E_SHARED_ROOT")
        c2 = next(c for c in v["conditions"] if c["rule"] == "two_independent_approvals")
        self.assertEqual(c2["detail"]["shared_root"], "rootShared")

    def test_external_resolver_edge_table_can_establish_shared_root(self):
        from adjudicator.model import event_digest, make_isolate, make_proposal, make_receipt
        tenant, ep = "t-rr", "EP-RR"
        iso = make_isolate(tenant, ep, 10, 10, 200)
        d = event_digest(iso)

        def raw_approval(aid, who):
            # 故意不提供 control_chain，只能依赖外部控制边表解析根。
            return {"kind": "APPROVAL", "tenant_id": tenant, "endpoint_id": ep,
                    "vt": 12, "approval_id": aid, "approver": who,
                    "auth_gen": 1, "validity": [10, 200]}

        receipts = [
            make_receipt("ISO", 11, iso),
            make_receipt("R-A1", 13, raw_approval("AP1", "u1")),
            make_receipt("R-A2", 13, raw_approval("AP2", "u2")),
        ]
        prop = make_proposal("P-RR", tenant, ep, 30, d, 1, ["AP1", "AP2"])
        # 无解析器且无链：approver 自身即根，u1 != u2 -> 独立 -> ALLOW。
        self.assertTrue(evaluate(prop, receipts)["allowed"])
        # 外部边表把两人最终都追到 rootZ -> 同根否决。
        resolver = RootResolver({"u1": "mgrX", "mgrX": "rootZ", "u2": "rootZ"})
        v = evaluate(prop, receipts, resolver=resolver)
        self.assertFalse(v["allowed"])
        self.assertEqual(v["primary_reason"], "E_SHARED_ROOT")


class CuratedEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = build_curated()

    def test_every_curated_case_matches_expected(self):
        for key, c in self.cases.items():
            v = evaluate(c["proposal"], c["receipts"])
            self.assertEqual(v["primary_reason"] or "ALLOW", c["expect"], msg=key)

    def test_dual_time_split_late_receipt(self):
        g = self.cases["gold_late_in_window"]
        # 有效时间回看：第二批准在 vt=12 即生效 -> 最早 12（尽管 rt=60 才到）。
        self.assertEqual(earliest_by_valid_time(g["proposal"], g["receipts"])["earliest"], 12)
        # 当时已知重放：归档点 40 尚不知第二批准 -> 否决。
        at40 = evaluate_known_then(g["proposal"], g["receipts"], 40)
        self.assertEqual(at40["primary_reason"], "E_NOT_TWO_APPROVALS")
        # 实际可知最早可行动点 = 60（迟到回执到达的同一 tick，闭包含）。
        self.assertEqual(earliest_actionable_time(g["proposal"], g["receipts"])["earliest"], 60)
        self.assertTrue(evaluate_known_then(g["proposal"], g["receipts"], 60)["allowed"])

    def test_late_beyond_window_has_no_actionable_point(self):
        c = self.cases["late_expired"]
        self.assertEqual(earliest_by_valid_time(c["proposal"], c["receipts"])["earliest"], 12)
        self.assertIsNone(earliest_actionable_time(c["proposal"], c["receipts"])["earliest"])
        at80 = evaluate_known_then(c["proposal"], c["receipts"], 80)
        self.assertEqual(at80["primary_reason"], "E_WINDOW_EXPIRED")

    def test_idempotent_replay_after_archive(self):
        g = self.cases["gold_late_in_window"]
        iso = g["receipts"][0]
        replayed = g["receipts"] + [copy.deepcopy(iso), copy.deepcopy(iso)]
        v = evaluate(g["proposal"], replayed, at_vt=70)
        self.assertTrue(v["allowed"])
        self.assertEqual(v["replay"]["identical_replays_deduped"], 2)

    def test_conflicting_same_id_is_flagged(self):
        g = self.cases["gold_late_in_window"]
        evil = copy.deepcopy(g["receipts"][0])
        evil["fact"]["window"] = [0, 1]  # 同 id 不同内容
        v = evaluate(g["proposal"], g["receipts"] + [evil], at_vt=70)
        self.assertIn(evil["receipt_id"], v["replay"]["conflicting_receipt_ids"])

    def test_earliest_matches_bruteforce_ticks(self):
        rep = check_earliest_bruteforce(self.cases, horizon=140)
        self.assertTrue(rep["passed"], rep["failures"])

    def test_bruteforce_helpers_agree_on_gold(self):
        g = self.cases["gold_late_in_window"]
        self.assertEqual(brute_force_earliest_tick(g["proposal"], g["receipts"], 140), 12)
        self.assertEqual(
            brute_force_earliest_tick(g["proposal"], g["receipts"], 140, known_then=True), 60
        )


class VetoProofTests(unittest.TestCase):
    def test_all_deny_proofs_verify_and_chain(self):
        prev = "0" * 64
        for c in build_curated().values():
            v = evaluate(c["proposal"], c["receipts"])
            if v["allowed"]:
                continue
            p = build_veto_proof(v, prev_proof_digest=prev)
            rep = verify_proof(p, expected_prev=prev)
            self.assertTrue(rep["ok"], rep["errors"])
            prev = p["proof_digest"]

    def test_tampered_claim_is_rejected(self):
        c = build_curated()["same_root"]
        p = build_veto_proof(evaluate(c["proposal"], c["receipts"]))
        p["primary_reason"] = "E_WINDOW_EXPIRED"
        rep = verify_proof(p)
        self.assertFalse(rep["ok"])
        self.assertFalse(rep["checks"]["proof_digest"])

    def test_resealed_logical_lie_still_rejected_by_logic_replay(self):
        c = build_curated()["same_root"]
        honest = build_veto_proof(evaluate(c["proposal"], c["receipts"]))
        lie = copy.deepcopy(honest)
        # 把第二批准改成异根，使嵌入证据在逻辑上变成 ALLOW。
        for r in lie["evidence_receipts"]:
            f = r["fact"]
            if f.get("approval_id") == "A-SR-2":
                f["control_chain"] = [f["approver"], "rootDifferent"]
                f["root_controller"] = "rootDifferent"
        # 攻击者持有 HMAC 密钥，对内容重新做摘要/封签。
        prev = lie["prev_proof_digest"]
        lie = finalize_proof(lie, prev_proof_digest=prev, signing_key=DEMO_SIGNING_KEY)
        rep = verify_proof(lie)
        self.assertFalse(rep["ok"])
        self.assertIn("logic_denied", rep["checks"])
        self.assertFalse(rep["checks"]["logic_denied"])

    def test_malformed_hex_proof_is_rejected_without_raising(self):
        c = build_curated()["same_root"]
        p = build_veto_proof(evaluate(c["proposal"], c["receipts"]))
        p["prev_proof_digest"] = "not-hex-at-all"  # 畸形十六进制
        rep = verify_proof(p)  # 不得抛异常
        self.assertFalse(rep["ok"])
        self.assertIn("proof_encoding", rep["checks"])
        self.assertFalse(rep["checks"]["proof_encoding"])

    def test_merkle_order_sensitivity_and_empty(self):
        h1 = sha256_hex("a")
        h2 = sha256_hex("b")
        self.assertNotEqual(merkle_root([h1, h2]), merkle_root([h2, h1]))
        self.assertEqual(len(merkle_root([])), 64)


class DecisionTableExhaustiveTests(unittest.TestCase):
    def test_full_factor_table_matches_reference(self):
        rep = decision_table()
        self.assertEqual(rep["cases"], 144)
        self.assertTrue(rep["passed"], rep["mismatches"][:5] + rep["proof_failures"][:2])


class BarrierFaultPointTests(unittest.TestCase):
    def test_revoke_exactly_landed_is_revoked(self):
        script = ("stage", "revoke")
        idx = fault_index_for(script, "revoke.post_barrier")
        w = DurableWorld()
        inj = FaultInjector(crash_at=idx)
        with self.assertRaises(Crash):
            StagingActor(w, inj).run_script(script)
        out = recover_world(w)
        self.assertEqual(out["outcome"], "REVOKED")
        self.assertIn("REVOKE", [r["rec"] for r in w.staging.stable])

    def test_revoke_before_barrier_is_lost_and_in_doubt_abort(self):
        script = ("stage", "revoke")
        idx = fault_index_for(script, "revoke.post_append")
        w = DurableWorld()
        inj = FaultInjector(crash_at=idx)
        with self.assertRaises(Crash):
            StagingActor(w, inj).run_script(script)
        out = recover_world(w)
        # REVOKE 未越屏障 -> 丢失；只剩 INTENT -> 存疑失败关闭。
        self.assertEqual(out["outcome"], "ABORTED_IN_DOUBT")
        self.assertNotIn("REVOKE", [r["rec"] for r in w.staging.stable])

    def test_receipt_lost_decision_landed_stands_with_gap(self):
        script = ("stage", "decide", "receipt")
        idx = fault_index_for(script, "receipt.post_append")
        w = DurableWorld()
        inj = FaultInjector(crash_at=idx)
        with self.assertRaises(Crash):
            StagingActor(w, inj, bindings_valid=True).run_script(script)
        out = recover_world(w)
        self.assertEqual(out["outcome"], "DECISION_STANDS_RECEIPT_GAP")
        self.assertEqual(out["durable_verdict"], "APPROVE")
        self.assertTrue(out["receipt_gap"])
        self.assertEqual(out["stable_receipt_ids"], [])

    def test_happy_path_restores(self):
        w = DurableWorld()
        StagingActor(w, FaultInjector()).run_script(("stage", "receipt", "decide", "apply"))
        out = recover_world(w)
        self.assertEqual(out["outcome"], "RESTORED")
        self.assertTrue(out["restored_effective"])

    def test_post_decision_revoke_blocks_apply_and_is_revoked(self):
        w = DurableWorld()
        StagingActor(w, FaultInjector()).run_script(
            ("stage", "decide", "revoke", "apply")
        )
        out = recover_world(w)
        self.assertEqual(out["outcome"], "REVOKED")
        self.assertEqual(out["durable_verdict"], "APPROVE")  # 已落盘决定不可翻案
        self.assertTrue(out["post_decision_revoke"])
        self.assertFalse(out["restored_effective"])

    def test_short_sequences_all_fault_points_exhaustive(self):
        rep = enumerate_crash_sequences(max_len=4)
        self.assertTrue(rep["passed"], rep["violations"][:3])
        self.assertIsNotNone(rep["revoke_just_landed"])
        self.assertIsNotNone(rep["receipt_lost_decision_landed"])
        # 5 + 25 + 125 + 625 个序列
        self.assertEqual(rep["scripts"], sum(len(ALPHABET) ** k for k in range(1, 5)))
        self.assertGreater(rep["fault_runs"], 1000)

    def test_short_sequences_invalid_binding_too(self):
        rep = enumerate_crash_sequences(max_len=3, bindings_valid=False)
        self.assertEqual(rep["violation_count"], 0)
        self.assertTrue(rep["safety_passed"])


class FileFsyncBarrierTests(unittest.TestCase):
    def test_real_file_reopen_two_named_outcomes(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            # A: revoke fsync-landed.
            sp, qp = td / "a_staging.jsonl", td / "a_receipts.jsonl"
            s, q = FileBarrierLog(sp), FileBarrierLog(qp)
            s.append({"rec": "INTENT"}); s.barrier()
            s.append({"rec": "REVOKE"}); s.barrier()
            s.crash(); q.crash()
            ra = recover_from_disk(sp, qp)
            self.assertEqual(ra["outcome"], "REVOKED")

            # B: decision fsync-landed, receipt never barred -> lost.
            sp2, qp2 = td / "b_staging.jsonl", td / "b_receipts.jsonl"
            s, q = FileBarrierLog(sp2), FileBarrierLog(qp2)
            s.append({"rec": "INTENT"}); s.barrier()
            s.append({"rec": "DECISION", "verdict": "APPROVE"}); s.barrier()
            q.append({"rec": "RECEIPT", "receipt_id": "rcpt-x"})
            s.crash(); q.crash()
            rb = recover_from_disk(sp2, qp2, required_receipt="rcpt-x")
            self.assertEqual(rb["outcome"], "DECISION_STANDS_RECEIPT_GAP")

    def test_torn_tail_line_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "torn.jsonl"
            log = FileBarrierLog(p)
            log.append({"rec": "DECISION", "verdict": "DENY"})
            log.barrier(); log.close()
            with open(p, "a", encoding="utf-8") as fh:
                fh.write('{"rec":"DECISIO')
            recs = FileBarrierLog.read_disk(p)
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0]["verdict"], "DENY")


class ScalePartitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bulk = generate_bulk()

    def test_at_least_sixty_thousand_partitioned_receipts(self):
        self.assertGreaterEqual(self.bulk["total_receipts"], 60000)
        counts = self.bulk["store"].partition_counts()
        self.assertEqual(len(counts), 8)
        self.assertTrue(all(n == 8000 for n in counts.values()))

    def test_full_sweep_matches_every_endpoint_expectation(self):
        store = self.bulk["store"]
        grouped = {}
        for r in store.read_all():
            grouped.setdefault((r["tenant_id"], r["endpoint_id"]), []).append(r)
        bad = []
        for p in self.bulk["proposals"]:
            v = evaluate(p, grouped[(p["tenant_id"], p["endpoint_id"])], at_vt=p["at_vt"])
            got = v["primary_reason"] or "ALLOW"
            if got != self.bulk["expected"][(p["tenant_id"], p["endpoint_id"])]:
                bad.append((p["endpoint_id"], got))
        self.assertEqual(bad, [])

    def test_local_correction_accesses_exact_partition_and_matches_full(self):
        bulk = generate_bulk()  # 独立数据集，避免污染类共享 store
        store = bulk["store"]
        sample = bulk["correction_sample"]
        corrected = build_shared_root_correction(store, sample)
        proposal = next(
            p for p in bulk["proposals"]
            if p["tenant_id"] == sample["tenant"]
            and p["endpoint_id"] == sample["endpoint"]
        )
        audit = audit_local_correction(
            store, bulk["proposals"],
            tenant=sample["tenant"], endpoint=sample["endpoint"],
            proposal=proposal, target_receipt_id=sample["target_receipt_id"],
            corrected_receipt=corrected,
        )
        for name, passed in audit["checks"].items():
            self.assertTrue(passed, msg=f"{name}: {audit}")
        self.assertEqual(audit["local_access"], [sample["tenant"]])
        self.assertEqual(audit["changed_tenants_by_full_rescan"], [sample["tenant"]])
        self.assertEqual(audit["local_result"]["primary_reason"], "E_SHARED_ROOT")

    def test_cross_tenant_same_receipt_id_does_not_shadow_partition(self):
        # 两个不同租户使用了相同 receipt_id 但内容不同：全量路径不得让它们互相遮蔽，
        # 否则会破坏“局部读分区 == 读全量”。
        from adjudicator.model import event_digest, make_isolate, make_proposal, make_receipt
        ep = "EP-DUP-ID"
        iso_a = make_isolate("tA", ep, 10, 10, 200)
        iso_b = make_isolate("tB", ep, 10, 10, 200)
        d_a, d_b = event_digest(iso_a), event_digest(iso_b)
        r_a = make_receipt("DUP-ID", 11, iso_a)
        r_b = make_receipt("DUP-ID", 11, iso_b)  # 同 id、跨租户、不同摘要
        combined = [r_a, r_b]
        p_a = make_proposal("PA", "tA", ep, 30, d_a, 1, ["AP-MISSING"])
        p_b = make_proposal("PB", "tB", ep, 30, d_b, 1, ["AP-MISSING"])

        for p, own_only in ((p_a, [r_a]), (p_b, [r_b])):
            full = evaluate(p, combined)
            local = evaluate(p, own_only)
            # C1 摘要绑定必须通过（证明本租户 isolate 未被另一租户同 id 记录顶掉），
            # 于是首要原因落到 C2 缺批准，而不是 E_NO_ISOLATION/E_DIGEST_MISMATCH。
            self.assertEqual(full["primary_reason"], "E_NOT_TWO_APPROVALS")
            self.assertEqual(local["primary_reason"], full["primary_reason"])
            c1 = next(c for c in full["conditions"]
                      if c["rule"] == "bind_original_isolation_digest")
            self.assertTrue(c1["passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
