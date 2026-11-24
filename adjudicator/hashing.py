"""规范编码与密码学承诺原语（标准库）。

所有跨进程/落盘/进入证明的结构都先做 *规范 JSON* 编码：
键排序、无多余空白、UTF-8、不转义非 ASCII，从而同样的逻辑结构在
任何机器/任何插入顺序下得到同样的字节与摘要。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

ZERO_HEX = "0" * 64


def canonical_bytes(obj: Any) -> bytes:
    """返回对象的规范 JSON 字节。只接受 JSON 可序列化结构。"""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_text(obj: Any) -> str:
    return canonical_bytes(obj).decode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest_obj(obj: Any) -> str:
    """对任意 JSON 结构计算规范摘要（64 位十六进制）。"""
    return sha256_hex(canonical_bytes(obj))


def hmac_hex(key: bytes, message_hex: str) -> str:
    """对一个十六进制摘要字节做 HMAC-SHA256，返回十六进制封签。"""
    return hmac.new(key, bytes.fromhex(message_hex), hashlib.sha256).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a or "", b or "")


def merkle_root(leaf_hexes: list[str]) -> str:
    """对一组 *叶子摘要* 计算排序无关? 不——保持给定顺序的 Merkle 根。

    空列表返回空串的 SHA-256。奇数节点时复制最后一个节点（比特币式），
    保证任何人生成的根一致。
    """
    if not leaf_hexes:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in leaf_hexes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            nxt.append(hashlib.sha256(level[i] + level[i + 1]).digest())
        level = nxt
    return level[0].hex()


def set_commitment(digests: list[str]) -> str:
    """对一个 *无序* 摘要集合做承诺：先排序再取 Merkle 根。

    这样证据以何种顺序被枚举都不影响承诺值。
    """
    return merkle_root(sorted(digests))


def hash_chain_link(prev_hex: str, payload_digest: str) -> str:
    """哈希链一环：H(prev || payload_digest)。"""
    return sha256_hex(bytes.fromhex(prev_hex) + bytes.fromhex(payload_digest))
