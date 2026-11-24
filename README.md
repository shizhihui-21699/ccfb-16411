# TSTV — 付费电视控制字分享的对抗与追踪

用 Rust 实现的**控制字（CW）分享对抗**研究原型：当盗版团伙买一张合法卡、把卡里
解出的 CW 实时转发给成千上万台盗版机顶盒时，系统如何

1. **缩短 CW 有效期**并前瞻下发，压制盗版服务的可用性；
2. 给不同用户下发**可追溯的差异化授权信息**；
3. **定位是哪张卡在分享**，并撤销它；
4. 在以上全过程中，对**合法直播用户零卡顿**（追踪到单卡时有界、可计量的短暂停发除外）。

约束来自真实现网：**老机顶盒不可换**、**广播带宽极小**、**同一路视频的 CW 全网唯一**。

> 设计取舍与物理约束的完整论证见 [`docs/DESIGN.md`](docs/DESIGN.md)。
> 本文只给结论与用法。

---

## 一个必须先说清楚的物理事实

**控制字的值不能按用户区分。** 一路视频用 `CW_t` 加扰后只广播一份密文，所有端
必须用**同一个** `CW_t` 才能解出同一画面。"给每张卡发不同的 CW"在数学上不成立。

因此本系统把一切差异化都放在**与 CW 值无关的侧面**：下发通道（分组/band）、
下发**时刻**、每卡 EMM、回传回执。这既保住了零卡顿，也决定了追踪能力的上界
（详见下文"诚实的边界"）。

另一点常被想当然、实则错误：**"把候选子集 rekey，让分享卡失明，从而定位"不成立**
——分享卡是合法卡，rekey 后它会正常收到新密钥继续转发。任何"让分享卡解不出自己
ECM"的手段，必然同时打击同组所有合法卡。见 `docs/DESIGN.md` §3.2。

---

## 三层机制

| 层 | 机制 | 对合法用户 | 对盗版 |
|---|---|---|---|
| **① 短周期 + 前瞻广播** | CW 每 0.25–2 s 轮换；每周期重发未来 L 个周期的 ECM（多副本） | **零卡顿**（缓冲 L 个周期） | 转发延迟 + 抖动 → 周期性错过周期边界，服务质量劣化 |
| **② 分组测试定位** | A：下发时刻指纹（零干扰，定位到 band）；B：单 band 内短暂停发（有界干扰，定位到卡） | A 零卡顿；B 仅影响 ≤N/K 台、短促 | 盗版断流 → 1 bit oracle |
| **③ 每卡 EMM + 回执** | EMM 用每卡密钥 `K_card` 认证；回执 `ack=HMAC(K_card, epoch)` | 无影响 | 单卡撤销；克隆检测（同一 ack 两个 source） |

第三层的 `(分组, probe_id, epoch)` 组合就是**逐卡可追溯的差异化授权信息**；即便
广播，也只有目标卡能验证。

---

## 快速开始

```bash
cargo build --release

# 单个场景：稳态指标 + 追踪 + 克隆检测 + 撤销
./target/release/tstvd run --subs 4096 --measure 200 --seed 7

# 权衡曲线：前瞻深度 × 周期长度 vs 合法卡顿 / 盗版失效 / 带宽
./target/release/tstvd sweep --subs 256

# 分组数 vs 追踪轮数 / 探测字节 / 可行性
./target/release/tstvd bands --subs 4096
```

所有命令对给定 `--seed` **完全可复现**（无 OS 熵，全部确定性）。

## 实测结果（默认参数，`--seed 7`）

```
period 1000 ms | lookahead 4 | repeats 2 | bands 32 | loss 0.20%
ECM channel: 46.6 kbit/s, 49% of 96 kbit/s budget, 91 B/section

Legitimate viewers:  4096 boxes, 0 glitches
Pirate service:      relay latency 350±220 ms vs 3000 ms slack -> 0% failure
Tracing:  band 10 from delivery-timing fingerprint (external, zero-interference)
          card narrowed to 1 by suppression: 7747 bytes,
          cost 381 box-periods of bounded legit glitch
Clone detection:     flagged at epoch 0
Rectification:       revoked; 0 other-viewer glitches; pirate starved
```

**权衡曲线**（`sweep`，合法卡顿恒为 0，盗版失效随"前瞻时长"下降）：

| look | period | slack | pirate glitch% | ECM kbit/s |
|---:|---:|---:|---:|---:|
| 2 | 250 | 250 ms | 70.0 | 120.8 |
| 3 | 250 | 500 ms | 17.3 | 153.6 |
| 2 | 1000 | 1000 ms | 0.0 | 30.2 |

读法：前瞻越浅、周期越短，盗版越难受，但 ECM 带宽与丢包容错越紧。这组参数就是
现网要调的旋钮。`look=3, period=250ms` 是常见的甜点（合法 0 卡顿、盗版 17% 失效）。

---

## 诚实的边界（务必阅读）

- **追踪到"卡"有真实代价。** A 方案（时刻指纹）零干扰，但只能到分组（≈N/K 张卡）；
  B 方案能到单卡，但需在已定位的**单个 band** 内短暂停发 ECM，该子集合法盒会在
  停发窗口内**卡顿**。仿真逐次统计此代价（`affected_legit_glitches`），它被限制在
  单 band、短促、可计量。**不要把这说成"零代价"**。
- **"零卡顿"仅对稳态广播与 A 方案是构造性成立的**（靠前瞻缓冲 + 窗口重发 + 冗余）。
  丢包极端升高时 `L` 需相应加深（`shallow_lookahead...` 测试给出边界）。
- **指纹码是工程近似，不是 Tardos 可证界。** `tstv-trace::fingerprint` 在 q=8、
  c≤5 上经验验证"至少指认一名合谋者且无误伤"，但不宣称信息论最优；大规模合谋需
  更强码。
- **不防 `K_card` 物理提取。** 威胁模型是"攻击者能导出明文 CW"，不是"攻击者能读卡
  密钥"。后者是安全芯片/白盒领域，不在本仓库范围。
- **克隆检测依赖回传信道。** 纯广播卡只能靠分组测试定位，不能做克隆检测。

---

## 仓库结构

| crate | 职责 |
|---|---|
| `tstv-core` | 确定性密码（AES-128 / AES-CMAC / HMAC-SHA256 / KDF / CTR）、CRC-32、严格线路格式（ECM/EMM）、类型、时间窗口、确定性 RNG |
| `tstv-cas` | headend（ECM/EMM 生成、分组、key-segment 探测调度、带宽核算）；卡（EMM 校验、ECM 解密、CW 缓冲、回执）；机顶盒（播放仿真、卡顿统计） |
| `tstv-trace` | 分组测试控制器（band 内二分）、q 元指纹码与解码、克隆检测 |
| `tstvd` | 端到端仿真库 + CLI（`run` / `sweep` / `bands`） |

线路格式（严格、无隐式尾随字节、先验签后使用）见 `crates/tstv-core/src/wire.rs`
顶部注释。ECM 段落按 **key-segment 切分**，绝不让一个 ECM 跨密钥段——这是探测期间
合法盒零卡顿的关键。

## 测试

```bash
cargo test --release          # 77 项，含密码学 KAT、格式、零卡顿不变量、追踪、克隆
```

关键不变量测试：

- `legit_viewer_glitch_free_across_a_probe`——探测期间合法盒零卡顿，且断言探测**确实**
  切分了 ECM（非空转）。
- `tracing_locates_every_possible_traitor`——128 个订阅者位置**穷举**，全部定位正确。
- `rectification_after_steady_state_keeps_everyone_else_clean`——撤销后旁观者零卡顿。
- `shallow_lookahead_is_less_loss_tolerant_than_deep`——证明前瞻深度是丢包容错来源。
- `majority_coalitions_are_named_without_false_accusations`——指纹码合谋解码。
