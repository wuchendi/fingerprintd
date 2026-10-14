# fingerprintd — 设计文档

[English](DESIGN.md) · **中文**

> 面向**反欺诈 / 反自动化**的服务端设备指纹。判定以服务端为准:客户端只负责采集;
> 服务端签发一次性 challenge、做模糊匹配、融合被动信号,并返回
> `visitorId` + `confidence`。

本文是权威设计文档,实现以本文为准。全文分两部分 ——
**[架构](#架构)**(挑战-响应协议、信任边界与 HTTP 契约)与
**[模糊匹配](#模糊匹配)**(把原始分量变成 `visitorId` 的两阶段引擎)。章节编号是
稳定锚点,源码文档注释以 `architecture §N` / `fuzzy-matching §N` 引用它们。

## 目录

**[架构](#架构)**

1. [背景](#1-背景)
2. [目标与威胁模型](#2-目标与威胁模型)
3. [成功指标](#3-成功指标)
4. [架构:挑战-响应 + 服务端融合](#4-架构挑战-响应--服务端融合)
5. [HTTP 接口](#5-http-接口)
6. [数据模型](#6-数据模型)
7. [隐私与合规](#7-隐私与合规)
8. [部署目标](#8-部署目标)
9. [纵深防御控制](#9-纵深防御控制配置门控默认关闭)

**[模糊匹配](#模糊匹配)**

1. [问题定义](#1-问题定义)
2. [分量分类](#2-分量分类建模前提)
3. [存储表示](#3-存储表示)
4. [阶段一:候选集生成](#4-阶段一候选集生成blocking)
5. [阶段二:概率打分(Fellegi–Sunter)](#5-阶段二概率打分fellegisunter)
6. [confidence 输出](#6-confidence-输出)
7. [漂移与投毒防护](#7-漂移模板自适应与投毒防护)
8. [边界情况](#8-边界情况)
9. [参数估计与冷启动](#9-参数估计与冷启动)
10. [离线评估](#10-离线评估)
11. [数据结构与性能](#11-数据结构与性能)
12. [待解决问题](#12-待解决问题)

---

# 架构

## 1. 背景

纯客户端指纹(如开源的 FingerprintJS)存在结构性缺陷:

- **可伪造** —— id 在客户端用客户端可控的值计算得出。
- **无重放防护** —— 静态 id 被捕获一次后即可任意重复提交。
- **不精确** —— 精确的客户端哈希会*雪崩*:任一组件变化就让同一台设备看起来是新设备,
  而同型号设备之间又相互碰撞。
- **对抗性弱** —— 隐私浏览器 / 反指纹扩展会主动加噪。

| 问题 | 根因 | 方向 |
|---|---|---|
| 可伪造 | 信任客户端上报的值 | 用**客户端无法自报的被动信号**做交叉校验 |
| 无重放防护 | id 是静态的 | 绑定新鲜度证明的**一次性 challenge** |
| 不精确 | 精确客户端哈希 + 雪崩 | **服务端模糊匹配 + 多源融合** |

判定完全移到服务端;客户端只负责采集 —— 这正是 FingerprintJS Pro / DataDome /
Akamai 共同采取的路线。

---

## 2. 目标与威胁模型

在高风险动作(登录、注册、结账、优惠券核销)处,每个请求都产出一个稳定的
`visitorId` 和一个供风控引擎使用的 `confidence`:这是不是一台新设备、它是否关联到某台
已知设备、以及自报的浏览器特征是否与网络层一致(bot 检测)?

### 威胁模型

| 对手 | 能力 | 系统目标 |
|---|---|---|
| **L1 脚本** | curl / 脚本,无 JS | 必须拒绝(无采集 / TLS 不一致) |
| **L2 自动化** | 无头浏览器,运行 JS,伪造 UA/JS 值 | 通过被动信号 + 一致性识别 |
| **L3 高级** | curl-impersonate / uTLS 伪造 JA3/JA4 + 完整栈 | **降低 confidence + 交叉验证**,而非绝对封禁 |

不宣称有绝对防御。L3 对手可以伪造任何单一信号;价值在于**抬高伪造成本**和
**多信号一致性检测**,而非做到不可攻破。

### 目标

- **G1** —— 服务端签发一次性 challenge;结果绑定新鲜度,因此重放无效。
- **G2** —— 把客户端组件 + 被动网络信号融合为 `visitorId` + `confidence`。
- **G3** —— 用模糊匹配取代精确哈希,消除雪崩;稳定性优先于唯一性。
- **G4** —— 决策 P99 延迟 ≤ 50ms(不含客户端采集);单实例 ≥ 2k RPS。

### 非目标

- 不做完整的客户端 SDK UI/遥测框架 —— 只提供最小化的采集 + challenge 外壳。
- 不做不可攻破的防篡改(WASM 外壳抬高 hook 成本,并非决定性)。
- 不做跨站追踪 / 广告归因。
- 当前版本不做设备关联图(账号 ↔ 设备聚类);数据为之预留。

---

## 3. 成功指标

| 指标 | 定义 | 目标 |
|---|---|---|
| 稳定率 | 同一设备在两周内多次访问被重新解析到同一个 `visitorId` | ≥ 95% |
| 碰撞率 | 不同设备被解析到同一个 `visitorId` | ≤ 1% |
| L1/L2 检出 | 脚本 / 伪造请求被标为低 confidence | ≥ 90% |
| 决策 P99 | 提交 → 返回 `visitorId` | ≤ 50ms |
| 重放拒绝 | 拒绝过期 / 重用的 nonce | 100% |

> 稳定率/碰撞率目标需通过**针对带标注语料库的离线评测**验证 ——
> 见 [fuzzy-matching §10](#10-离线评估)。不得用合成 fixture 数据上报这些指标。

---

## 4. 架构:挑战-响应 + 服务端融合

### 4.1 新鲜度与身份(核心拆分)

匹配要求同一台设备每次都产出**相同**的稳定输出。因此证据被拆为两条永不混合的通道:

- **`stable_components`** —— 不混入 nonce;原始值进入指纹库并驱动身份匹配。
- **freshness proof(新鲜度证明)** —— 依赖服务端签发的 nonce,证明本次采集是实时的;
  它**绝不**参与身份匹配。

**重放防护**建立在两层之上,按权威性排序:

1. **一次性 nonce(主锁)。** 服务端铸造一个短 TTL、单次使用的 nonce,并在消费时销毁。
   重用或过期的 nonce 以 `401` 拒绝。这是决定性保证。
2. **Nonce probe(纵深防御,可选)。** 当配置了 `probe_key` 时,服务端在 challenge 中
   声明一个确定性变换;客户端返回 `hex(HMAC-SHA256(key, nonce))`,在 WASM 中计算。这证明
   客户端按协议实时计算,而非重放固定值。它是叠加在一次性 nonce 之上的纵深,而非主锁 ——
   密钥随客户端 WASM 发布且可被提取,因此它抬高门槛却非决定性。

> 早期设计曾把 nonce 混入 canvas/audio 的绘制种子(`challenge_response`)。它已被移除:
> 依赖"每次输出都不同"的新鲜度无法被服务端独立验证,而一次性 nonce 可以。HMAC probe
> 取代它成为实时采集证明。

### 4.2 被动信号与信任边界

TLS JA3/JA4 **不是**高熵的单设备标识符,也**不是**不可伪造的:

- 低熵 —— 数百万台同型号 Chrome 实例共享同一个 JA3,因此它不能作为 `visitorId` 的来源。
- 可伪造 —— curl-impersonate / uTLS 可以构造任意 ClientHello。

它真正的价值在于**一致性交叉校验**,加权计入 `confidence`,绝不计入 `visitorId`:

- JS 声称是 Chrome/Windows 但 JA4 是 Python/Go 栈 → 强异常,confidence 大幅降低。
- IP 信誉(数据中心 / 代理 / 风险源)→ 辅助,非决定性。

**部署约束(硬性)。** 连接层信号只能由终结客户端 TLS 连接的一方捕获。在 Cloudflare 代理
之后,源站看到的是 CF↔源站这一段,因此客户端层信号必须被透传过来。

- **当前拓扑** —— Cloudflare 提取 JA3/JA4 并通过 header 转发。可用性取决于账户(JA4 header
  绑定 Bot Management、Enterprise):存在 → 使用;**缺失 → 自动降级**(连接层信号被中和并
  降权,请求**不**被封禁;通过 `CF-Connecting-IP` 获得的真实客户端 IP 仍供 IP 信誉使用)。
- **信任边界(fail-closed)。** 边缘注入的被动信号 header **仅**在部署被配置为信任边缘
  (`trust_edge_headers`)时才读取;否则任何客户端提供的副本都被忽略。这可防止客户端塞入
  伪造的 JA4。自管理的 nginx/envoy 边缘注入其自身受信 JA4 header 属未来扩展。

### 4.3 模糊匹配与候选集生成

匹配**不是**哈希查表,也不能线性扫描整个库。分两阶段:(1) blocking / LSH 召回把库压缩到
数十至数百个候选;(2) 加权概率打分(Fellegi–Sunter)对其排序并决策。完整文档见下文的
[模糊匹配](#模糊匹配)部分。

### 4.4 客户端采集:复用 FingerprintJS / BotD

客户端只负责采集;判定在服务端(§4)。采集器复用现成的 MIT 库,而非重新发明:

| 库 | 许可证 | 复用方式 | 边界 |
|---|---|---|---|
| **FingerprintJS**(OSS) | MIT | npm 依赖;取其**原始 `components`** 作为 `stable_components` | 丢弃其客户端 `visitorId` 哈希 |
| **BotD**(OSS) | MIT | npm 依赖;bot 信号折入服务端 `confidence` | 客户端信号可伪造,属次要输入 |

Nonce probe(§4.1)为自研 —— FingerprintJS 不会对服务端 nonce 计算带密钥的变换。客户端
适配器在提交前把 FingerprintJS 嵌套的 `{value, duration}` 组件结构和键名映射到服务端
schema,使真实浏览器 probe 可被匹配。见 [`packages/client`](packages/client/README.md)。

---

## 5. HTTP 接口

两种部署目标(§8)提供相同的通信契约。

### GET /challenge

```
200: {
  nonce: string,          // one-time, server-issued
  expires_in: 30,         // seconds (nonce_ttl_secs)
  collect: {
    stable: [...],                 // stable component ids to gather
    challenge: {
      seed: string,                // = nonce; seeds the rendered canvas/audio challenge
      targets: [...],              // active-probe targets to render, e.g. ["canvas", "audio"]
      verify?: {                   // advertised only when a probe_key is configured
        alg: "HMAC-SHA256",
        input: "nonce",
        encoding: "hex"
      }
    }
  }
}
```

### POST /identify

```
Req: {
  nonce: string,
  stable_components: { ... },   // raw values, no nonce mixed in
  probe?: string,               // hex(HMAC-SHA256(key, nonce)); required when the server enforces the probe
  ts?: number,                  // client Unix ms; checked only when the timestamp window is enforced
  integrity?: {                 // known-answer client integrity probe verdicts; top-level so they never enter matching
    canvas: "ok" | "noise" | "unavailable", webgl: ..., audio: ..., rect: ...
  }
}
200: {
  visitorId: string,
  confidence: 0.0..1.0,         // DECISION confidence, not identity trust — see §6
  decision: "match" | "review" | "new_device",
  is_new_device: boolean,
  collision_risk: boolean,
  signals: {                    // for the risk engine; raw passive signals are never echoed
    ua_tls_consistent: boolean,
    ip_risk: "low" | "medium" | "high",
    client_integrity: "ok" | "noise" | "unavailable",  // 客户端完整性综合判定
    persona_coherence: "consistent" | "mismatch" | "unknown"  // UA 操作系统族 vs 字体集,仅展示
  }
}
401: nonce expired / reused, or an enforced probe / timestamp check failed
```

请求体是 `deny_unknown_fields` —— 出现预期外的顶层键即以 `400` 拒绝(两个栈皆然)。当设置了
`response_signing_key` 时,成功响应会额外携带 `x-fp-timestamp` + `x-fp-signature`
(`hex(HMAC-SHA256(key, be64(issuedMs) ++ body))`)。

被动信号(JA4/IP)由服务端从连接层获取(§4.2),**绝不**从客户端请求体接受。

`client_integrity` 综合了 SDK 的四个**已知答案完整性探针**:采集器向浏览器提出几个未改动的
Chromium 必然精确回答的问题(不透明像素的 canvas `toDataURL` → `getImageData` 无损往返、
WebGL 纯色 clear、离线渲染的 `ConstantSourceNode`、1/64 px 可表示偏移处的
`getBoundingClientRect`),逐探针报告 `ok` / `noise` / `unavailable`。指纹加噪(反检测)浏览器
四个都答错 —— 这是第一个能在**单次请求**内、从采集器内部观察到此类浏览器的信号。判定以顶层
字段随请求发送 —— 绝不放进 `stable_components` —— 因此不可能进入 `visitorId`;任一 `noise`
即为 `noise`,否则任一 `ok` 即为 `ok`,否则为 `unavailable`(字段缺失、API 不可用、材料畸形 ——
始终中性)。该分带**默认只做展示**:合法的隐私工具(Brave farbling、canvas 屏蔽器)会触发同样的
探针,所以 `noise` 的置信度下调是可选项(`integrity_penalty_enabled` /
`FP_INTEGRITY_PENALTY_ENABLED`),在拿到真实流量的误报率之前保持关闭。两个栈通过共享核心
(`fingerprintd::signals::ClientIntegrity`)计算同一结果。

`persona_coherence` 把 UA 声称的操作系统族和采集到的 `fonts` 集合做交叉检查:Windows 或 macOS
的 UA,而字体集里**一个**该系统的核心字体都没有(取自 FingerprintJS 探测列表的极小精选集 ——
Calibri、Segoe UI Light、MS UI Gothic…… / Helvetica Neue、Menlo、Gill Sans)即为
`mismatch` —— 借来的人设,例如伪装浏览器在 Linux 容器里扮演 Windows,隐藏了宿主字体却没有添加任何
Windows 字体。其他系统族、缺 UA 或缺 `fonts` 数组读作 `unknown`。仅展示:绝不改变 `confidence`
或 `visitorId`。如实说明局限:安装了 Windows 字体集的操作者(或伪造字体度量的二进制)能通过;它只是
提高成本。声称的 UA 从顶层组件的几种拼写读取,对真实 SDK 载荷则回退到 BotD 信号
(`botd.signals.userAgent.value`)—— 同一回退也让 UA↔TLS 交叉检查(§4.2)第一次能看到 SDK 流量。

### DELETE /visitor/{id}

GDPR 被遗忘权(§7)。受 admin-key 门控(`admin_key`):未设置 ⇒ 该路由被禁用。擦除是幂等的 ——
即使该 visitor 不存在也返回 `204`。

---

## 6. 数据模型

- **fingerprints** —— `visitorId` → 各组件的加盐哈希、blocking key、首次/末次可见时间、
  观测计数。原始值**不**存储(§7);类别组件是加盐哈希,集合组件是逐元素哈希(保留
  Jaccard)。见 [fuzzy-matching §3](#3-存储表示)。
- **nonce** —— `nonce` → `{issued_at, used}`,TTL = `expires_in`,使用时销毁。
- **frequency** —— 供 `u_i` 稀有度估计使用的逐值计数
  ([fuzzy-matching §9](#9-参数估计与冷启动))。

**`confidence` 语义。** `confidence` 是**决策置信度**,不是身份可信度:一台从未见过的
全新设备会以高决策置信度被判为 `new_device`(引擎确信它是新的)。风控消费方必须读取
`is_new_device` / `decision` 来判断身份可信度,不得把高 confidence 的 `new_device` 当作
高可信度身份。

---

## 7. 隐私与合规

存储派生指纹比纯客户端方案敏感度更高,因此:

- **法律依据** —— 在 GDPR/CCPA/PIPL 下,设备指纹通常属于个人数据;反欺诈一般基于正当利益,
  需要一份 DPIA 记录。
- **数据最小化** —— 只存加盐哈希,绝不存原始组件值
  (§6 / [fuzzy-matching §3](#3-存储表示))。
- **保留期** —— 超过 `retention_secs` 的记录被清扫并删除;`0` 关闭清扫。
- **擦除** —— `DELETE /visitor/{id}`(§5)实现被遗忘权。
- **严格输入** —— 请求体上的 `deny_unknown_fields` 防止静默接受未建模字段。
- **目的限制** —— 仅用于反欺诈;用于广告/追踪会改变法律依据,超出范围。
- **透明度** —— 在隐私政策中披露设备指纹。

---

## 8. 部署目标

一套引擎([`crates/fp-core`](crates/fp-core)),两个宿主。客户端对两者均无需改动即可工作;
二者通过在双侧运行的共享 parity fixture 被约束为行为一致。

| 关注点 | 原生服务端(`crates/fingerprintd`) | 边缘 Worker(`apps/edge`) |
|---|---|---|
| 运行时 | Axum / Tokio,长驻进程 | Cloudflare Worker(V8 isolate,按请求) |
| Nonce 存储 | 内存,单次使用 + TTL,有界 + 回收 | Durable Object(原子 check-and-burn + TTL alarm) |
| 指纹库 | 内存倒排索引 + 频次表,有界/驱逐 | D1(SQLite):`templates` + `blocking_index` |
| 计算 | 原生 `fingerprintd` | `fingerprintd` 编译为 WASM(`crates/fp-wasm`) |
| 被动信号 | 完整 JA4/IP 融合(§4.2) | 默认中立;JA4/IP 需受信边缘 |
| 密钥 | config / env | Worker Secrets |

原生存储是进程本地的:重启会重新铸造设备,因此要在生产上获得单实例稳定的 `visitorId`,
需要一个持久后端(D1/Durable Object 接缝,或位于 `NonceStore` / `FingerprintStore` /
`CandidateSource` trait 之后的外部存储)。持久化部署见 [`apps/edge`](apps/edge/README.md)。

**下游消费者。** `visitorId` + `confidence` + `signals` 是给*风控引擎*的输入,本身不是
终判 —— fingerprintd 刻意不持有账号状态与行为历史(非目标,§2)。需要 allow/challenge/deny
决策的调用方在其之上叠加一层。edge Worker 以一个 config 门控的 `POST /checkin/assess` 路由
提供参考示例([`apps/edge`](apps/edge/README.md)):把 `/identify` 输出与账号/设备/IP/时序聚合
结合,为每日签到反刷打分,而指纹核心保持不变。由 [playground](apps/web/README.md) 演示。

---

## 9. 纵深防御控制(配置门控,默认关闭)

三者皆为 fail-closed,且仅在其密钥被设置后才激活:

- **Nonce probe**(`probe_key`,§4.1)—— 校验 WASM 计算出的 `probe`;错误/缺失 ⇒ `401`。
  同一密钥必须烘焙进客户端 WASM 构建。
- **响应签名**(`response_signing_key`,§5)—— 对每个 `/identify` 成功响应签名,使客户端
  能检测篡改。
- **时间戳窗口**(`enforce_ts_window` + `ts_skew_secs`,§5)—— 限定请求 `ts` 可以有多陈旧。

它们是叠加在一次性 nonce 和 TLS 之上的纵深,后两者仍为主控。内嵌的客户端密钥可被提取,
不得被提升为决定性控制。

---

# 模糊匹配

> [architecture §4.3](#43-模糊匹配与候选集生成)背后的第二阶段匹配引擎。
> 目标([architecture §3](#3-成功指标)):稳定率 ≥ 95%,碰撞率 ≤ 1%,
> 决策 P99 ≤ 50ms,单实例 ≥ 2k RPS。

## 1. 问题定义

输入:一次观测的稳定组件集合,`probe = {c_1, …, c_n}`。
输出:匹配到的 `visitorId`(同一设备)或新设备判定,外加一个
`confidence`。

三条约束彼此拉扯:

- **De-avalanche(去雪崩)** —— 单个组件变化(浏览器自动升级、新装字体、
  外接显示器)不得铸造出新的 `visitorId`。
- **Anti-collision(防碰撞)** —— 两台同型号 + 同浏览器版本的不同设备不得
  解析为同一个 `visitorId`。
- **高吞吐** —— 百万级记录库不可能对每次请求做线性扫描。

两个核心决策:

1. **两阶段** —— 候选生成(§4)→ 概率打分(§5)。
2. **打分采用 Fellegi–Sunter (FS) 概率化记录链接模型**(§5),
   而非手工调参的加权平均 —— FS 的两个参数 `m_i / u_i`
   分别对 *稳定性* 与 *区分度* 建模,天然对应上述两种失败模式。

---

## 2. 分量分类(建模前提)

每个组件在两条正交轴上被刻画 —— 这是每一个权重的来源:

- **Stability(稳定性)** —— 同一设备多次访问间该组件保持不变的概率
  (→ FS `m_i`)。
- **Distinctiveness(区分度)** —— 两台不同设备取相同值的概率(→ FS `u_i`;
  越罕见 `u` 越低)。

| Component | Type | Stability | Distinctiveness | Notes |
|---|---|---|---|---|
| WebGL vendor+renderer | category | high | medium | GPU 硬件,极少变化 |
| Canvas hash | category | low | high | 驱动/浏览器升级时整体翻转;隐私/反检测浏览器会按会话加噪 |
| Audio fingerprint | category | high | med-high | 音频栈,稳定 |
| Font list | set | medium | high | 增量变化 → Jaccard/MinHash |
| Timezone / language / platform | category | high | low | 低熵,单独不足 |
| Screen resolution | category(`"WxH"`,长边在前) | medium | med-low | 外接显示器会改变它 |
| CPU cores / device memory | numeric | high | low | |
| Browser version / UA | version | **low** | medium | **雪崩之源**,每隔几周自动升级 |
| Plugins / mimeTypes | set | medium | medium | |

> 关键洞见:UA/浏览器版本频繁变化 —— 精确哈希会不断铸造出
> "新设备",这正是 FingerprintJS 的雪崩问题。在 FS 下它的 `m_i`
> 很低,因此一次失配几乎不惩罚;它会自动淡出。

---

## 3. 存储表示

为满足数据最小化([architecture §7](#7-隐私与合规)),在保留匹配能力的同时
从不存储原始值:

- **Category 组件** —— 存储加盐哈希 `H(salt || value)`。仍支持
  相等比较 + 频次统计(用于 `u_i`)。
- **Set 组件(fonts 等)** —— 存储 **逐元素哈希** 后的集合
  `{H(f) for f in fonts}`。逐元素哈希 **保留 Jaccard**,因此集合
  相似度 + MinHash 仍然可用。
- **Numeric 组件** —— 存储该值或分桶后的值。
- 每个 `visitorId` 还存储:各组件的最新值、`first_seen`、
  `last_seen`、`observation_count`,以及用于漂移的逐组件新鲜度(§7)。

---

## 4. 阶段一:候选集生成(blocking)

目标:从百万级记录库中,以近 O(1) 得到数十到数百个候选,
**且不漏掉真正的匹配**(召回优先)。

不能只用单个精确键 —— 任意一个组件变化就会漏掉。要用
**多个相互独立的分块键,取并集** 以获得召回冗余:

- `K1 = H(webgl_renderer || platform || timezone)` —— 一个高稳定性子集
- `K2 = H(audio_hash || cpu_cores || device_memory)` —— 一个不相交的高稳定性子集
- `K3 = MinHash-LSH(font set)` 的 band 桶 —— 容忍字体的增量变化
- (可选)`K4 = Simhash(all-component tokens)` 的 Hamming 近邻桶

召回率 = 1 − P(所有键都漏)。每个键使用不相交的稳定组件子集,因此
当某个组件恰好变化时,另一个键仍能命中。候选集 = ∪(各键命中的
`visitorId`)。

**索引** —— `blocking_key → set<visitorId>` 倒排索引。MinHash-LSH:
`band signature → bucket → visitorId`。

**热块膨胀** —— 一个流行配置(默认 Safari 的 iPhone)会让某个块
变得巨大(信息量低)。缓解:

- 限制块大小;超过上限后该键携带的信息很少、无法收窄
  候选 —— 必须由第二阶段打分(§5)来消歧;
- 超上限的丢弃 **必须记录日志**(不得静默截断),从而杜绝
  "看似覆盖实则没有"。

---

## 5. 阶段二:概率打分(Fellegi–Sunter)

对每个候选 `cand` 与 `probe`,逐组件比较并累加
对数似然比。

### 5.1 单分量一致性 `agree_i`

- Category —— 哈希相等 → agree,否则 disagree。
- Set —— Jaccard `J = |A∩B| / |A∪B|`;`J ≥ τ` → agree(τ ≈ 0.8),否则
  线性插值(见 5.3)。
- Numeric —— 相等或同桶 → agree。
- Version —— 主版本相同 → agree;相邻主版本 → partial(见 5.3);否则 disagree。

### 5.2 两个参数

- `m_i = P(agree_i | same device)` —— 由 **高置信匹配的回访** 估计;
  对稳定性建模。
- `u_i = P(agree_i | different device)` —— 由该组件取值在 **库中的频率** 估计;
  对区分度建模。罕见值 → `u_i` 极低 → 相等是强证据;
  常见的 Chrome/Windows 值 → `u_i` 高 → 相等几乎不算数。

### 5.3 单分量得分

```
agree:      w_i = log2( m_i / u_i )                      // positive; rarer = larger
disagree:   w_i = log2( (1 - m_i) / (1 - u_i) )          // negative; more stable = more negative
partial (set/version): w_i = J · log2(m_i/u_i) + (1-J) · log2((1-m_i)/(1-u_i))
missing (either side lacks it): w_i = 0                  // not compared, not scored (see §8)
```

合计:`score(cand) = Σ_i w_i`。

**为什么该模型是对的:**

- **De-avalanche** —— UA 的 `m_i` 很低 → `(1-m_i)/(1-u_i)` ≈ 1,`log` ≈ 0 → 一次 UA
  失配几乎不惩罚。
- **Anti-collision** —— 两台同型号设备在高熵组件
  (canvas/fonts)上不一致,而它们的 `m_i` 很高 → 该不一致带来大的负值,
  把总分拉到阈值以下 → 判为不同设备。
- **Low-entropy auto-fade(低熵自动淡出)** —— timezone/language 的 `u_i` 很高 → 一致几乎不
  加分,因此"同处一个时区"永远不会强制匹配。

### 5.4 判定

取最高候选 `best`;两个阈值 `T_hi > T_lo`:

- `score(best) ≥ T_hi` → **同一设备**;返回其 `visitorId`,应用漂移(§7)。
- `T_lo ≤ score(best) < T_hi` → **疑似**;返回该 `visitorId`,但降低
  置信度并打上 `review` 标记。
- `score(best) < T_lo` → **新设备**;铸造一个全新的 `visitorId`。
- **≥ 2 个候选 ≥ T_hi 且差距很小** → 碰撞风险;取最高者并抬起
  一个 `collision_risk` 标记。

---

## 6. confidence 输出

`confidence ∈ [0,1]`,由三部分融合而成(规则加权;当前版本无
学习模型):

- **Match margin(匹配裕度)** —— `score(best)` 超出 `T_hi` 的幅度,加上与次高者的差距
  (差距越大 → 越确定)。
- **Passive-signal consistency(被动信号一致性)** —— JA4/UA 一致 → 提升;不一致 → 大幅
  下调(防伪造的核心,[architecture §4.2](#42-被动信号与信任边界))。
- **Component completeness(组件完整度)** —— 有多少组件参与了比较;缺失越多 → 置信度
  越低(§8)。

---

## 7. 漂移(模板自适应)与投毒防护

若无漂移,已存组件(UA 等)会陈旧,几次浏览器升级后匹配
质量下降。规则:

- **仅在高置信匹配(≥ T_hi)时** 刷新该 `visitorId` 的最新
  组件值与 `last_seen`。
- **模板投毒防御** —— 攻击者可能通过反复的低置信匹配,把 A 的指纹缓慢
  改造成 B。因此:
  - 低置信 / review 命中 **不** 触发更新;
  - 原始观测历史被保留;更新只覆盖
    "最新值"层,绝不覆盖历史;
  - 单次更新的变化幅度有上界;异常跳变会被标记。

---

## 8. 边界情况

- **隐私浏览器屏蔽 canvas(null/空)** —— 缺失组件计 `w_i = 0`
  且不参与比较。绝不能把"null canvas"当作可匹配的值 —— 否则
  所有隐私用户在该组件上都一致 → 大规模碰撞。缺失越多 → 置信度越低。
- **Brave 式的按会话 canvas 随机化** —— 该组件在同一设备的每次访问
  都变化 → `m_i → 0`,因此 FS 会自动忽略它,回退到
  fonts/audio/webgl。进阶:识别出 canvas 始终变化的一类人群,并为其屏蔽
  该组件(未来)。
- **企业金镜像 / 完全相同的 VM** —— 真正不同的设备却有
  完全相同的指纹;模糊匹配无法区分它们,会发生碰撞。必须
  回退到 IP + 账户行为;这是一条 **已知能力边界**,
  本引擎不解决。

---

## 9. 参数估计与冷启动

- `u_i` —— 维护逐组件取值的频次计数,在存储中增量更新。
- `m_i` —— 需要"同设备回访"标签。冷启动使用 **先验**(依 §2
  分类:高稳定性 = 0.95,中 = 0.80,低 = 0.50);上线后,
  在高置信匹配回访上做 **EM 迭代** 使其收敛。这是一个
  迭代过程,而非一次性完成。
- 冷库阶段:一切都被判为新设备;分块索引与
  频率统计随时间逐步积累。

---

## 10. 离线评估

证明 §3 的目标,首先需要一个带标注的评测集:

- **Ground truth(真值)** —— 用登录态 / 长效 cookie 标注"同一设备的
  多次访问"。
- **Stability rate(稳定率)** —— 同设备回访被解析到单一 `visitorId` 的比例
  (扫描 `T_hi`)。
- **Collision rate(碰撞率)** —— 不同设备被解析到单一 `visitorId` 的比例。
- 网格搜索 `T_lo / T_hi / τ` 与组件先验;绘制
  稳定–碰撞权衡曲线以设定阈值。
- 上线后,持续把 review/collision_risk 样本重新喂给人工评审,
  以精炼 `m_i/u_i` 与阈值。

> 本仓库附带一个合成夹具,用于 **方向性地** 检验打分接线 ——
> 它是冒烟测试,而非数值目标的证据。它打印的
> 比率不得当作生产环境的稳定率/碰撞率数字来报告。

---

## 11. 数据结构与性能

| Use | Structure | Notes |
|---|---|---|
| Blocking inverted index | `key → set<visitorId>` | 内存 / Redis Set / PG GIN |
| MinHash-LSH | `band signature → bucket` | 面向 set 组件的召回 |
| Fingerprint library | `visitorId → component hashes + frequency material + timestamps` | KV / D1 / PG |
| Frequency stats | `component value hash → count` | 估计 `u_i` |

性能:第一阶段为 O(candidates);第二阶段为 O(candidates × 常数
组件数)。把候选控制在低数百量级即可满足 P99 ≤ 50ms。在
原生服务器上,倒排索引 + 打分常驻内存;频率/指纹库
持久化层异步落盘。

---

## 12. 待解决问题

1. set 组件的 MinHash band 数量 / τ —— 需要真实数据测量。
2. EM 收敛 `m_i` 需要多少带标注的回访样本。
3. 块大小上限,以及超上限人群的回退方案(强制高熵一致?)。
4. 频率统计的时间衰减窗口(对陈旧值降权?)。
5. 是否按设备人群分层做参数估计(移动端 vs 桌面端的 `m/u` 不同)。
