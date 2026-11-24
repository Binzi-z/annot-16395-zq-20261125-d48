"""屏障 + 故障点驱动的恢复暂存状态机与崩溃恢复。

持久化模型
----------
每条日志有两级写入：

- ``append``  → 进入易失 ``pending``（尚未落盘，崩溃即丢）。
- ``barrier`` → 一个持久化屏障：把 pending 一次性提交到 stable；
  文件实现里紧接着 flush + ``os.fsync``，这才是“正好落盘”的边界。

故障注入器在一组确定编号的 *故障点* 上可令进程“崩溃”：崩溃会丢弃所有日志
的 pending，但已越过屏障进入 stable / 已 fsync 的记录保留。于是：

- “撤销正好落盘” = 崩溃点恰好选在 REVOKE 的 ``post_barrier`` 故障点：
  REVOKE 已 stable，恢复必须判为 REVOKED，绝不能恢复终端。
- “回执已丢但决定已落盘” = DECISION 已越过屏障 stable，而所需异地回执只
  append 未 barrier 就在下一个故障点崩溃丢失：恢复必须让已落盘决定成立，
  同时报 ``RECEIPT_GAP``，且不得翻案。

安全不变量（由 exhaustive 中的独立预言机逐条核对）
--------------------------------------------------
I1 任何 APPLIED 之前必有 APPROVE DECISION，且该 APPLIED 之前不得有 REVOKE。
I2 判为 RESTORED ⇔ 日志中存在合法 APPLIED。
I3 存在 REVOKE 且无合法 APPLIED ⇒ 结果必须是 REVOKED。
I4 DECISION_STANDS_GAP ⇒ 必有 APPROVE DECISION 且所需回执不在 stable。
I5 恢复结果对同一 stable 日志是确定、可重复的。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable

from .hashing import digest_obj

# 结果常量（model 中已有一部分，这里补齐 NONE / POST 标志语义）
OUT_NONE = "NONE"
OUT_RESTORED = "RESTORED"
OUT_REVOKED = "REVOKED"
OUT_DOUBT_ABORT = "ABORTED_IN_DOUBT"
OUT_DENIED = "DENIED"
OUT_DECIDED_NOT_APPLIED = "DECIDED_NOT_APPLIED"
OUT_DECISION_STANDS_GAP = "DECISION_STANDS_RECEIPT_GAP"

DEFAULT_REQUIRED_RECEIPT = "rcpt-approval-evidence-1"
STAGE_BOUND_DIGEST = digest_obj({"drill": "original-isolation", "endpoint": "EP-STAGE"})


class Crash(Exception):
    """注入的模拟崩溃。point 为故障点编号，label 为人类可读位置。"""

    def __init__(self, point: int, label: str) -> None:
        super().__init__(f"CRASH at #{point} {label}")
        self.point = point
        self.label = label


class BarrierLog:
    """内存版屏障日志：stable 模拟介质上已落盘部分，pending 为易失写。"""

    def __init__(self, name: str) -> None:
        self.name = name
        self.stable: list[dict[str, Any]] = []
        self.pending: list[dict[str, Any]] = []
        self._lsn = 0

    def append(self, rec: dict[str, Any]) -> dict[str, Any]:
        rec = dict(rec)
        rec.setdefault("lsn", self._lsn)
        self._lsn += 1
        self.pending.append(rec)
        return rec

    def barrier(self) -> int:
        n = len(self.pending)
        self.stable.extend(self.pending)
        self.pending.clear()
        return n

    def crash(self) -> None:
        # 断电：所有尚未越过屏障的易失写丢失。
        self.pending.clear()

    def all_live(self) -> list[dict[str, Any]]:
        return self.stable + self.pending


class FileBarrierLog(BarrierLog):
    """真实文件版：barrier 时写 JSONL 并 flush+fsync，可在 Windows 上重开核对。

    pending 在 barrier 之前甚至还没写进 OS（保留在进程缓冲），因此模拟崩溃
    丢弃 pending 是确定的；已 barrier 的行已 fsync，重开文件必然仍在。
    """

    def __init__(self, path: str | os.PathLike[str], name: str | None = None) -> None:
        super().__init__(name or Path(path).stem)
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = None

    def _ensure_open(self):
        if self._fh is None:
            self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
        return self._fh

    def barrier(self) -> int:
        if not self.pending:
            return 0
        fh = self._ensure_open()
        for rec in self.pending:
            fh.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
        n = len(self.pending)
        self.stable.extend(self.pending)
        self.pending.clear()
        return n

    def crash(self) -> None:
        self.pending.clear()
        if self._fh is not None:
            try:
                self._fh.close()
            finally:
                self._fh = None

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    @classmethod
    def read_disk(cls, path: str | os.PathLike[str]) -> list[dict[str, Any]]:
        """从磁盘重读全部完整 JSON 行；末尾半行（真崩溃可能产生）被忽略。"""
        p = Path(path)
        if not p.exists():
            return []
        records: list[dict[str, Any]] = []
        text = p.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # 崩溃在一次写行中间：丢弃不完整尾行。
                continue
        return records


class DurableWorld:
    """暂存日志 + 异地回执日志两个独立屏障域。"""

    def __init__(self, required_receipt: str = DEFAULT_REQUIRED_RECEIPT) -> None:
        self.staging = BarrierLog("staging")
        self.receipts = BarrierLog("receipts")
        self.required_receipt = required_receipt

    def crash(self) -> None:
        self.staging.crash()
        self.receipts.crash()


class FaultInjector:
    """顺序编号故障点；crash_at 等于某点编号时在该点注入崩溃。"""

    def __init__(self, crash_at: int | None = None) -> None:
        self.crash_at = crash_at
        self.seen = 0
        self.fired: tuple[int, str] | None = None
        self.labels: list[str] = []

    def hit(self, world: DurableWorld, label: str) -> None:
        idx = self.seen
        self.seen += 1
        self.labels.append(label)
        if self.crash_at is not None and idx == self.crash_at:
            self.fired = (idx, label)
            world.crash()
            raise Crash(idx, label)


# 操作字母表（短序列穷举用）
OP_STAGE = "stage"
OP_REVOKE = "revoke"
OP_DECIDE = "decide"
OP_APPLY = "apply"
OP_RECEIPT = "receipt"
ALPHABET = (OP_STAGE, OP_REVOKE, OP_DECIDE, OP_APPLY, OP_RECEIPT)


class StagingActor:
    """按操作字母表推进暂存协议。每个操作内含确定的屏障/故障点。"""

    def __init__(
        self,
        world: DurableWorld,
        injector: FaultInjector,
        *,
        bindings_valid: bool = True,
    ) -> None:
        self.w = world
        self.inj = injector
        self.bindings_valid = bindings_valid

    def run_script(self, ops: Iterable[str]) -> None:
        for op in ops:
            self.run_op(op)

    def run_op(self, op: str) -> None:
        fn = {
            OP_STAGE: self._stage,
            OP_REVOKE: self._revoke,
            OP_DECIDE: self._decide,
            OP_APPLY: self._apply,
            OP_RECEIPT: self._receive_receipt,
        }[op]
        fn()

    # -- 各操作 -------------------------------------------------------------

    def _stage(self) -> None:
        self.inj.hit(self.w, "stage.enter")
        if any(r["rec"] == "INTENT" for r in self.w.staging.all_live()):
            self.inj.hit(self.w, "stage.already")
            return
        self.w.staging.append(
            {
                "rec": "INTENT",
                "proposal_id": "P-STAGE-1",
                "bound_digest": STAGE_BOUND_DIGEST,
                "required_receipt": self.w.required_receipt,
            }
        )
        self.inj.hit(self.w, "stage.post_append")
        self.w.staging.barrier()
        self.inj.hit(self.w, "stage.post_barrier")

    def _revoke(self) -> None:
        self.inj.hit(self.w, "revoke.enter")
        if any(r["rec"] == "REVOKE" for r in self.w.staging.all_live()):
            self.inj.hit(self.w, "revoke.already")
            return
        self.w.staging.append(
            {"rec": "REVOKE", "target_digest": STAGE_BOUND_DIGEST, "source": "remote-cancel"}
        )
        self.inj.hit(self.w, "revoke.post_append")
        self.w.staging.barrier()
        self.inj.hit(self.w, "revoke.post_barrier")

    def _receive_receipt(self) -> None:
        self.inj.hit(self.w, "receipt.enter")
        if any(
            r.get("receipt_id") == self.w.required_receipt
            for r in self.w.receipts.all_live()
        ):
            self.inj.hit(self.w, "receipt.already")
            return
        self.w.receipts.append(
            {"rec": "RECEIPT", "receipt_id": self.w.required_receipt, "ok": True}
        )
        self.inj.hit(self.w, "receipt.post_append")
        self.w.receipts.barrier()
        self.inj.hit(self.w, "receipt.post_barrier")

    def _decide(self) -> None:
        self.inj.hit(self.w, "decide.enter")
        log = self.w.staging.all_live()
        if any(r["rec"] == "DECISION" for r in log):
            self.inj.hit(self.w, "decide.already")
            return

        has_intent = any(r["rec"] == "INTENT" for r in log)
        revoked = any(r["rec"] == "REVOKE" for r in log)
        if not has_intent:
            verdict, reason = "DENY", "E_NO_STAGING_INTENT"
        elif not self.bindings_valid:
            verdict, reason = "DENY", "E_BINDING_INVALID"
        elif revoked:
            verdict, reason = "DENY", "E_REVOKED"
        else:
            verdict, reason = "APPROVE", None

        self.w.staging.append({"rec": "DECISION", "verdict": verdict, "reason": reason})
        self.inj.hit(self.w, "decide.post_append")
        self.w.staging.barrier()  # 决定的提交点：越过此屏障即“决定已落盘”
        self.inj.hit(self.w, "decide.post_barrier")

    def _apply(self) -> None:
        self.inj.hit(self.w, "apply.enter")
        log = self.w.staging.all_live()
        if any(r["rec"] == "APPLIED" for r in log):
            self.inj.hit(self.w, "apply.already")
            return
        approve_i = next(
            (i for i, r in enumerate(log) if r["rec"] == "DECISION" and r["verdict"] == "APPROVE"),
            None,
        )
        if approve_i is None:
            self.inj.hit(self.w, "apply.reject_no_approval")
            return
        # 只要当前日志里已有任何撤销（无论在决定前后、但尚未 APPLIED），
        # 就不得执行实际恢复效果。这是“撤销优先于效果点”的安全闸。
        if any(r["rec"] == "REVOKE" for r in log):
            self.inj.hit(self.w, "apply.reject_revoked")
            return
        self.w.staging.append({"rec": "APPLIED", "effect": "endpoint-unisolated"})
        self.inj.hit(self.w, "apply.post_append")
        self.w.staging.barrier()
        self.inj.hit(self.w, "apply.post_barrier")


# ---------------------------------------------------------------------------
# 恢复折叠（实现侧分类器）
# ---------------------------------------------------------------------------

def classify_stable(
    staging_records: list[dict[str, Any]],
    stable_receipt_ids: set[str] | None = None,
    required_receipt: str = DEFAULT_REQUIRED_RECEIPT,
) -> dict[str, Any]:
    """从已落盘的 stable 记录确定性折叠出崩溃恢复结果。"""
    stable_receipt_ids = stable_receipt_ids or set()
    recs = staging_records

    def first_index(pred) -> int | None:
        return next((i for i, r in enumerate(recs) if pred(r)), None)

    intent_i = first_index(lambda r: r["rec"] == "INTENT")
    decision_i = first_index(lambda r: r["rec"] == "DECISION")
    applied_i = first_index(lambda r: r["rec"] == "APPLIED")
    revoke_is = [i for i, r in enumerate(recs) if r["rec"] == "REVOKE"]

    decision = recs[decision_i] if decision_i is not None else None
    verdict = decision.get("verdict") if decision else None

    # 合法 APPLIED：其前有 APPROVE 决定，且其前没有任何 REVOKE。
    legal_applied = False
    if applied_i is not None:
        prior_approve = any(
            i < applied_i and recs[i]["rec"] == "DECISION" and recs[i].get("verdict") == "APPROVE"
            for i in range(applied_i)
        )
        revoke_before_apply = any(i < applied_i for i in revoke_is)
        legal_applied = prior_approve and not revoke_before_apply

    revoke_present = bool(revoke_is)
    receipt_gap = required_receipt not in stable_receipt_ids

    result: dict[str, Any] = {
        "outcome": OUT_NONE,
        "durable_verdict": verdict,
        "decision_reason": decision.get("reason") if decision else None,
        "decision_immutable": decision is not None,
        "receipt_gap": receipt_gap,
        "revoke_present": revoke_present,
        "restored_effective": legal_applied,
        "post_decision_revoke": bool(
            decision_i is not None and any(i > decision_i for i in revoke_is)
        ),
        "counts": {
            "intent": intent_i is not None,
            "decisions": sum(r["rec"] == "DECISION" for r in recs),
            "revokes": len(revoke_is),
            "applied": applied_i is not None,
        },
    }

    if legal_applied:
        # 实际恢复效果已落盘；若其后才有撤销，属于“恢复后再撤销/再隔离”，
        # 不能追溯成“从未恢复”，但要明确标记。
        result["outcome"] = OUT_RESTORED
        result["revoked_after_restore"] = any(
            i > applied_i for i in revoke_is
        ) if applied_i is not None else False
        return result

    # 没有合法 APPLIED 时，撤销对暂存恢复有绝对否决权。
    if revoke_present:
        result["outcome"] = OUT_REVOKED
        return result

    if decision_i is not None:
        if verdict == "DENY":
            result["outcome"] = OUT_DENIED
        else:  # APPROVE 已落盘且无撤销
            result["outcome"] = (
                OUT_DECISION_STANDS_GAP if receipt_gap else OUT_DECIDED_NOT_APPLIED
            )
        return result

    if intent_i is not None:
        result["outcome"] = OUT_DOUBT_ABORT
        return result

    result["outcome"] = OUT_NONE
    return result


def recover_world(world: DurableWorld) -> dict[str, Any]:
    receipt_ids = {
        r.get("receipt_id")
        for r in world.receipts.stable
        if r.get("rec") == "RECEIPT"
    }
    out = classify_stable(
        list(world.staging.stable), receipt_ids, world.required_receipt
    )
    out["stable_staging"] = list(world.staging.stable)
    out["stable_receipt_ids"] = sorted(x for x in receipt_ids if x)
    return out


def recover_from_disk(
    staging_path: str | os.PathLike[str],
    receipt_path: str | os.PathLike[str],
    required_receipt: str = DEFAULT_REQUIRED_RECEIPT,
) -> dict[str, Any]:
    srecs = FileBarrierLog.read_disk(staging_path)
    rrecs = FileBarrierLog.read_disk(receipt_path)
    rids = {r.get("receipt_id") for r in rrecs if r.get("rec") == "RECEIPT"}
    out = classify_stable(srecs, rids, required_receipt)
    out["stable_staging"] = srecs
    out["stable_receipt_ids"] = sorted(x for x in rids if x)
    return out
