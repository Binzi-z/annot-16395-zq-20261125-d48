"""可独立验证的否决证明（Veto Proof）。

设计目标：第三方 *只拿到证明本身*（无需六万分租回执全库）就能核验
“在该双时态坐标与当时已知证据下，恢复确实必须被否决”，并且任何对结论、
坐标、证据的篡改都会导致摘要/封签/逻辑复核之一失败。

层次：
1. 自包含：嵌入当时知识截止下该终端的全部已知回执与提案、坐标、条件表。
2. 承诺：证据集合做无序集合承诺（排序 Merkle），整个证明做规范摘要。
3. 哈希链：``chain = H(prev || proof_digest)``，可串联多次裁决/证明。
4. 封签：HMAC-SHA256（演练用内置演示密钥；真实部署应取自 DPAPI/密钥保管，
   工作区 .gitignore 已排除 *.key/*.dpapi）。封签证明来源，摘要证明未被篡改。
5. 逻辑复核：验证器 *不信任* 证明里声称的原因，而是用嵌入证据重跑引擎，
   要求重算得到相同的失败规则集且结论确为 DENY。因此即使有人持有密钥
   对“谎言”正确封签，逻辑复核仍会识破。

注意信任边界：单证明能证明“给定嵌入证据，否决成立且证据未被篡改”。
“当时是否还存在被裁决器隐瞒的、rt<=k 的回执”属于完整性问题，由分区日志
Merkle 根/全量核对锚定（见 partitions.py 与 6 万回执核对）。
"""

from __future__ import annotations

from typing import Any

from .engine import evaluate
from .hashing import (
    ZERO_HEX,
    constant_time_equals,
    hash_chain_link,
    hmac_hex,
    set_commitment,
    digest_obj,
)

PROOF_SCHEMA = "veto-proof/v1"

# 仅用于离线安全演练的合成 HMAC 密钥。
DEMO_SIGNING_KEY = b"drill-16395-demo-veto-signing-key"


def _proof_core(proof: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in proof.items() if k not in ("proof_digest", "chain_digest", "seal")}


def finalize_proof(
    payload: dict[str, Any],
    *,
    prev_proof_digest: str = ZERO_HEX,
    signing_key: bytes | None = DEMO_SIGNING_KEY,
) -> dict[str, Any]:
    """填充 proof_digest / chain_digest / seal。也供“伪造后重新封签”的健壮性测试使用。"""
    payload["prev_proof_digest"] = prev_proof_digest
    proof_digest = digest_obj(_proof_core(payload))
    payload["proof_digest"] = proof_digest
    payload["chain_digest"] = hash_chain_link(prev_proof_digest, proof_digest)
    if signing_key is not None:
        payload["seal"] = hmac_hex(signing_key, proof_digest)
    else:
        payload.pop("seal", None)
    return payload


def build_veto_proof(
    verdict: dict[str, Any],
    *,
    adjudicator_id: str = "offline-adjudicator",
    prev_proof_digest: str = ZERO_HEX,
    signing_key: bytes | None = DEMO_SIGNING_KEY,
) -> dict[str, Any]:
    if verdict["allowed"]:
        raise ValueError("只能为否决(DENY)结论构造 veto proof")

    evidence = verdict["evidence_receipts"]
    payload: dict[str, Any] = {
        "schema": PROOF_SCHEMA,
        "proof_type": "VETO",
        "adjudicator_id": adjudicator_id,
        "logical_issued_at": verdict["view"]["at_vt"],
        "view": verdict["view"],
        "proposal": verdict["proposal"],
        "claimed_decision": verdict["decision"],
        "primary_reason": verdict["primary_reason"],
        "failed_rules": verdict["failed_rules"],
        "conditions": verdict["conditions"],
        "evidence_receipt_ids": verdict["evidence_receipt_ids"],
        "evidence_receipts": evidence,
        "evidence_commitment": set_commitment([digest_obj(r) for r in evidence]),
        "replay": verdict["replay"],
    }
    return finalize_proof(
        payload, prev_proof_digest=prev_proof_digest, signing_key=signing_key
    )


def verify_proof(
    proof: dict[str, Any],
    *,
    signing_key: bytes | None = DEMO_SIGNING_KEY,
    expected_prev: str | None = None,
) -> dict[str, Any]:
    """独立验证证明。返回 ``{"ok": bool, "errors": [...], "checks": {...}}``。"""
    errors: list[str] = []
    checks: dict[str, bool] = {}

    def check(name: str, ok: bool, err: str) -> None:
        checks[name] = ok
        if not ok:
            errors.append(err)

    if not isinstance(proof, dict) or proof.get("schema") != PROOF_SCHEMA:
        return {"ok": False, "errors": ["MALFORMED_PROOF_SCHEMA"], "checks": {}}

    stored_digest = proof.get("proof_digest", "")
    recomputed_digest = digest_obj(_proof_core(proof))
    digest_ok = constant_time_equals(stored_digest, recomputed_digest)
    check("proof_digest", digest_ok, "PROOF_DIGEST_MISMATCH: 证明内容被改动或摘要不正确")

    # 证据集合承诺
    evidence = proof.get("evidence_receipts", [])
    recommit = set_commitment([digest_obj(r) for r in evidence])
    check(
        "evidence_commitment",
        constant_time_equals(recommit, proof.get("evidence_commitment", "")),
        "EVIDENCE_COMMITMENT_MISMATCH",
    )

    # 哈希链 / HMAC。对畸形十六进制字段做防护：验证器面对被故意构造的恶意证明
    # 也应返回 ok=False，而不是让 bytes.fromhex 抛异常。
    link_base = stored_digest if digest_ok else recomputed_digest
    prev = proof.get("prev_proof_digest", ZERO_HEX)
    encoding_ok = True
    expect_chain = None
    try:
        if not isinstance(prev, str):
            raise ValueError("prev_proof_digest 不是字符串")
        expect_chain = hash_chain_link(prev, link_base)
    except (ValueError, TypeError) as exc:
        encoding_ok = False
        check("proof_encoding", False, f"MALFORMED_DIGEST_HEX: {exc}")

    if encoding_ok:
        check(
            "hash_chain",
            constant_time_equals(expect_chain, proof.get("chain_digest", "")),
            "HASH_CHAIN_MISMATCH",
        )
        if expected_prev is not None:
            check(
                "expected_prev",
                constant_time_equals(prev, expected_prev),
                "UNEXPECTED_PREV_PROOF",
            )

        # HMAC 来源封签
        if signing_key is not None:
            seal = proof.get("seal", "")
            try:
                expect_seal = hmac_hex(signing_key, link_base)
                check("hmac_seal", constant_time_equals(seal, expect_seal),
                      "HMAC_SEAL_INVALID")
            except (ValueError, TypeError) as exc:
                check("hmac_seal", False, f"HMAC_HEX_ERROR: {exc}")
        else:
            checks["hmac_seal_skipped"] = True

    # 逻辑复核：绝不信任 claimed/failed_rules，用嵌入证据重跑。
    # 同样做总防护：证明缺 proposal/view 等字段时返回不可验证而非抛异常。
    replay = None
    try:
        proposal = proof["proposal"]
        at_vt = proof["view"]["at_vt"]
        replay = evaluate(proposal, evidence, at_vt=at_vt, known_by_rt=None)
        check("logic_denied", replay["decision"] == "DENY",
              "LOGIC_LIE: 嵌入证据重算结果不是 DENY")

        claimed = {(f["rule"], f["reason_code"]) for f in proof.get("failed_rules", [])}
        actual = {(f["rule"], f["reason_code"]) for f in replay["failed_rules"]}
        check(
            "failed_rules_match",
            claimed == actual,
            f"FAILED_RULES_MISMATCH: claimed={sorted(map(str, claimed))} "
            f"actual={sorted(map(str, actual))}",
        )
        check(
            "claimed_decision",
            proof.get("claimed_decision") == replay["decision"],
            "CLAIMED_DECISION_MISMATCH",
        )
        check(
            "primary_reason",
            proof.get("primary_reason") == replay["primary_reason"],
            "PRIMARY_REASON_MISMATCH",
        )
    except (KeyError, TypeError, ValueError) as exc:
        check("logic_replay", False,
              f"LOGIC_REPLAY_ERROR: {type(exc).__name__}: {exc}")

    return {"ok": not errors, "errors": errors, "checks": checks, "replay_verdict": replay}
