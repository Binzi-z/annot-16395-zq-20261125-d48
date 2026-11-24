"""离线双时态恢复裁决器（仅依赖 Python 3.12 标准库）。

模块划分：
- hashing:    规范 JSON、SHA-256、Merkle 承诺、HMAC 封签
- model:      纯 JSON 记录 schema 与构造器（事件/回执/批准/授权代）
- roots:      根控制人解析（独立性判定）
- engine:     双时态裁决、四项强制绑定、最早可恢复点
- proof:      可独立验证的否决证明
- durable:    屏障/故障点持久暂存、崩溃恢复 FSM、真实 fsync 文件日志
- exhaustive: 决策表 + 短序列 x 故障点独立穷举
- partitions: 分租户分区存储、访问审计、局部更正 vs 全量核对
- synth:      确定性合成数据（>=60000 条回执）与精选剧本
- demo:       端到端报告
"""

__version__ = "1.0.0"
