"""根控制人解析与“批准独立性”判定。

两个批准即便 approver 身份不同，只要沿控制/委派关系向上追到同一个
*根控制人*，就属于同一控制域，不满足“独立批准”。这是题面的硬条件。

本模块既支持从一张控制边表解析根（带环检测），也支持直接校验批准中
内嵌的控制链（使单租户分区即可自证，不必跨区读全局控制目录）。
"""

from __future__ import annotations

from typing import Iterable, Mapping


class ControlCycleError(ValueError):
    pass


class RootResolver:
    """从 ``controlled_by[node] = parent`` 边表解析最终根控制人。"""

    def __init__(self, controlled_by: Mapping[str, str] | None = None) -> None:
        self.parent: dict[str, str] = dict(controlled_by or {})
        self._cache: dict[str, str] = {}

    def set_parent(self, node: str, parent: str) -> None:
        self.parent[node] = parent
        self._cache.clear()

    def root_of(self, node: str) -> str:
        if node in self._cache:
            return self._cache[node]
        path: list[str] = []
        seen: set[str] = set()
        cur = node
        while cur in self.parent:
            if cur in seen:
                raise ControlCycleError(f"控制关系存在环: {' -> '.join(path + [cur])}")
            seen.add(cur)
            path.append(cur)
            cur = self.parent[cur]
        for n in path:  # 路径压缩
            self._cache[n] = cur
        return cur

    def roots_of(self, nodes: Iterable[str]) -> dict[str, str]:
        return {n: self.root_of(n) for n in nodes}


def embedded_root(approval: dict) -> str:
    """取批准内嵌控制链的根，并校验链首确为 approver。"""
    chain = approval.get("control_chain")
    if not chain:
        # 没有链时退化为 approver 自身即根。
        return approval["approver"]
    if chain[0] != approval["approver"]:
        raise ControlCycleError("批准控制链首节点与 approver 不一致")
    return chain[-1]


def independent_pair(a: dict, b: dict, resolver: RootResolver | None = None) -> bool:
    """两个批准是否由不同根控制人最终控制。"""
    if resolver is not None:
        ra = resolver.root_of(a["approver"])
        rb = resolver.root_of(b["approver"])
    else:
        ra = embedded_root(a)
        rb = embedded_root(b)
    return ra != rb


def distinct_independent_roots(approvals: Iterable[dict]) -> set[str]:
    return {embedded_root(a) for a in approvals}
