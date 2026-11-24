#!/usr/bin/env python3
"""安全处置预案的双时态恢复裁决 —— 一键离线裁决/自检入口。

Windows + Python 3.12 标准库，无第三方依赖。

用法：
    python solution.py            # 运行全部演示与硬性核对，输出报告
    python -m unittest -v test_adjudicator   # 运行独立测试套件

退出码 0 表示全部核对通过；非 0 表示存在失败。
"""

from __future__ import annotations

import sys

from adjudicator.demo import main

if __name__ == "__main__":
    raise SystemExit(main())
