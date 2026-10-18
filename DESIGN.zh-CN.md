# fingerprintd — 设计文档

[English](DESIGN.md) · **中文**

> 面向**反欺诈 / 反自动化**的服务端设备指纹。判定以服务端为准:客户端只负责采集;
> 服务端签发一次性 challenge、做模糊匹配、融合被动信号,并记录 `visitor_id` +
> `confidence`,由客户后端按 `request_id` 以服务端到服务端的方式取回。

本文是权威设计文档,实现以本文为准。全文分两部分 ——
**[架构](#架构)**(challenge 协议、信任边界与 HTTP 契约)与
**[模糊匹配](#模糊匹配)**(把采集到的分量变成 `visitor_id` 的两阶段引擎)。章节编号是
稳定锚点,源码文档注释以 `architecture §N` / `fuzzy-matching §N` 引用它们。

## 目录

**[架构](#架构)**

1. [背景](#1-背景)
2. [目标与威胁模型](#2-目标与威胁模型)
3. [成功指标](#3-成功指标)
4. [一次性 challenge + 服务端融合](#4-架构一次性-challenge--服务端融合)
5. [HTTP 接口(Contract v1)](#5-http-接口contract-v1)
6. [数据模型](#6-数据模型)
7. [隐私与合规](#7-隐私与合规)
8. [部署目标](#8-部署目标)
9. [纵深防御控制](#9-纵深防御控制)

**[模糊匹配](#模糊匹配)**

1. [问题定义](#1-问题定义)
2. [分量分类](#2-分量分类封闭-schema)
3. [存储表示](#3-存储表示加盐存储形式)
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
| 无重放防护 | id 是静态的 | **一次性 nonce** + 强制时间戳窗口 |
| 不精确 | 精确客户端哈希 + 雪崩 | **服务端模糊匹配 + 多源融合** |

判定完全移到服务端;客户端只负责采集 —— 这正是 FingerprintJS Pro / DataDome /
Akamai 共同采取的路线。

---

## 2. 目标与威胁模型

在高风险动作(登录、注册、结账、优惠券核销)处,每个请求都产出一个稳定的
`visitor_id` 和一个供风控引擎使用的 `confidence`:这是不是一台新设备、它是否关联到某台
已知设备、以及自报的浏览器特征是否与网络层一致(bot 检测)?

### 威胁模型

| 对手 | 能力 | 系统目标 |
|---|---|---|
| **脚本** | curl / 脚本,无 JS | 必须拒绝(无 nonce / 无采集 / TLS 不一致) |
| **自动化** | 无头浏览器,运行 JS,伪造 UA/JS 值 | 通过被动信号 + 一致性识别 |
| **高级** | curl-impersonate / uTLS 伪造 JA3/JA4 + 完整栈,反检测浏览器 | **降低 confidence + 交叉验证**,而非绝对封禁 |

不宣称绝对防御。高级对手可以伪造任何单一信号;价值在于**抬高伪造成本**与
**多信号一致性检测**,而非不可攻破。

### 目标

- **G1** —— 服务端签发一次性 nonce 并强制时间戳窗口;捕获的请求无法重放。
- **G2** —— 融合客户端分量 + 被动网络信号,得出 `visitor_id` + `confidence`。
- **G3** —— 以模糊匹配取代精确哈希,消除雪崩;稳定性优先于唯一性。
- **G4** —— 判定 P99 延迟 ≤ 50ms(不含客户端采集);单实例 ≥ 2k RPS。
- **G5** —— 权威结果从不依赖浏览器:客户后端按 `request_id` 以服务端到服务端的方式读取。

### 非目标

- 不做完整的客户端 SDK UI / 遥测框架 —— 只提供最小的采集 + 提交 SDK。
- 不做不可攻破的客户端防篡改:所有客户端上报的值(components、`user_agent`、`botd`、`integrity`)都可被 hook,只作为证据,从不作为锁。
- 不做跨站追踪 / 广告归因。
- 核心不做设备关联图(账号 ↔ 设备聚类);边缘的签到评估(§8)是叠加在其上的参考消费方。

---

## 3. 成功指标

| 指标 | 定义 | 目标 |
|---|---|---|
| 稳定率 | 两周内同一设备多次访问被解析为同一 `visitor_id` | ≥ 95% |
| 碰撞率 | 不同设备被解析为同一 `visitor_id` | ≤ 1% |
| 脚本/自动化检出 | 脚本化 / 伪造请求被标为低置信 | ≥ 90% |
| 判定 P99 | 提交 → 返回 `visitor_id` | ≤ 50ms |
| 重放拒绝 | 过期 / 复用的 nonce,或 `ts` 超出窗口,被拒绝 | 100% |

> 稳定率/碰撞率目标以**基于标注语料的离线评估**为准 —— 见
> [fuzzy-matching §10](#10-离线评估)。不得用合成样例报告这两个数字。

---

## 4. 架构:一次性 challenge + 服务端融合

### 4.1 新鲜性与身份(核心拆分)

匹配要求同一设备每次产出**相同**的稳定输出。因此证据被拆成两条永不混合的通道:

- **`components`** —— 封闭分量 schema
  ([fuzzy-matching §2](#2-分量分类封闭-schema)),不混入 nonce。转换为加盐存储形式后
  驱动身份匹配。
- **新鲜性** —— 服务端签发的 `nonce` 与客户端 `ts`。它们证明请求是实时的,**从不**
  参与身份匹配。

**重放防护**由两道检查构成,二者始终强制:

1. **一次性 nonce。** `GET /challenge` 签发一个短 TTL 的随机 nonce
   (`FP_NONCE_TTL_SECS`,默认 30 秒,以 `expires_in` 告知)。`POST /identify` 消费它:
   对存活 nonce 的首次消费成功并将其销毁;未知、过期或复用的 nonce 以 `401` 拒绝。
2. **时间戳窗口。** `ts`(Unix 毫秒)必填,且必须落在服务端时间 `±FP_TS_SKEW_SECS`
   (默认 30 秒)内,否则 `401`。它在 nonce 之上进一步限制被捕获载荷的可用时长。

请求体在消费 nonce 之前完成校验,因此格式错误的请求(`400` / `415`)不会销毁 nonce。
nonce 先于时间戳检查,因此超出窗口的请求仍会销毁其 nonce。

### 4.2 被动信号与信任边界

TLS JA3/JA4 **不是**高熵的单设备标识,也**不是**不可伪造的:

- 低熵 —— 数百万同型号 Chrome 实例共享同一个 JA4,不能作为 `visitor_id` 的来源。
- 可伪造 —— curl-impersonate / uTLS 可以构造任意 ClientHello。

它真正的价值在于**一致性交叉校验**,加权进入 `confidence`,从不进入 `visitor_id`:

- **UA ↔ TLS。** 请求顶层的 `user_agent` 被归类(browser / automation / unknown),
  并与 JA4 揭示的协议栈对比(一组精选的真实浏览器 JA4 形态加上 cipher/extension 数量下限)。
  任一方向的矛盾为 `Mismatch`(confidence −0.5,`ua_tls_consistent: false`);一致为
  `Consistent`(+0.05);缺失或无法归类的 JA4 为 `Degraded` —— 中性,从不扣分,且
  `ua_tls_consistent` 保持 `true`。
- **IP 信誉** —— 由客户端 IP 得出的粗粒度等级(`low` / `medium` / `high`),以
  `signals.ip_risk` 暴露;它不改变 `confidence`。内置分类器是一张小型静态机房 CIDR 表
  (真实信誉数据源的示意替身);私有、回环与链路本地地址为 `low`。

**部署约束(硬性)。** 连接层信号只能由终结客户端 TLS 连接的一方采集,因此必须由服务前方的
边缘提供。每个宿主都从客户端无法写入的来源读取它们:

- **原生服务器。** 真实客户端 IP 取自 `cf-connecting-ip`,JA4 取自
  `cf-bot-management-ja4`,二者均由 Cloudflare 注入。**仅当** `trust_edge_headers`
  (`FP_TRUST_EDGE_HEADERS`)为 `true` 时才读取;默认 `false`(fail-closed),任何客户端
  自带的副本都被忽略,于是被动信号降级为中性,IP 速度也不计算。只有当源站位于 Cloudflare
  之后且源站 IP 白名单拒绝直连时才开启 —— 该设置取决于拓扑,在可直连的源站上开启会让
  客户端注入看似浏览器的 JA4。
- **边缘 Worker。** JA4 是 Cloudflare 自身的富化数据 `request.cf.botManagement.ja4`,
  客户端 IP 是 Cloudflare 在 Worker 前设置的 `cf-connecting-ip`;任何请求头都无法提供 JA4。
  没有 Bot Management(或不在 Cloudflare 上)时 JA4 缺失,判定降级。边缘还会把
  `request.cf.asn` / `asOrganization` 与一组精选的托管/机房/VPN ASN 对比;命中的 ASN
  把 `ip_risk` 提升到 `high`,从不降低。

### 4.3 模糊匹配与候选生成

匹配**不是**哈希查找,也不能线性扫描整个指纹库。分两阶段:(1)blocking / LSH 召回把库
压缩到有界的候选集;(2)加权概率打分(Fellegi–Sunter)对候选排序并判定。完整规范见下文
[模糊匹配](#模糊匹配)部分。

### 4.4 客户端采集:基于 FingerprintJS / BotD 的纯 TypeScript SDK

客户端只采集;判定在服务端(§4)。SDK
([`packages/client`](packages/client/README.md),npm `@cdlab/fingerprintd`)是纯
TypeScript,复用现有的 MIT 库:

| 库 | 许可证 | 复用方式 | 边界 |
|---|---|---|---|
| **FingerprintJS**(开源) | MIT | npm 依赖;其原始 `components` 被适配到封闭 schema | 丢弃其客户端 `visitorId` 哈希 |
| **BotD**(开源) | MIT | npm 依赖;其判定以 `botd: { bot, kind? }` 发送 | 客户端上报,仅暴露 |

一次 `collect()` 产出 `{ components, user_agent?, botd?, integrity? }`:

- **`components`** —— 适配器解开 FingerprintJS 的 `{value, duration}` 包装,把其分量名
  映射到封闭 schema 键([fuzzy-matching §2](#2-分量分类封闭-schema)),把每个值规范化为
  其类型(object/array 形式的 category 值取摘要),并丢弃所有未映射的分量。它只输出
  schema 键。
- **`user_agent`** —— 作为顶层字段的浏览器 UA。它不是分量;服务端只把它用于 UA↔TLS
  交叉校验(§4.2)和 persona 检查(§5)。
- **`botd`** —— BotD 判定,以 `signals.automation`(`detected` / `not_detected` /
  `unknown`)暴露;从不改变 `confidence`、判定或 `visitor_id`。
- **`integrity`** —— 四个已知答案完整性探针(`canvas`、`webgl`、`audio`、`rect`),
  见 §5 的 `client_integrity`。

`run()` 获取 challenge、采集、在 POST 前一刻写入 `ts` 并提交。浏览器端结果仅供展示
(§5,*信任链*)。

---

## 5. HTTP 接口(Contract v1)

两种部署目标(§8)提供同一份契约。所有 JSON 均为 `snake_case`;所有错误都是空 body 的
裸状态码。请求体在每一层都是封闭的:未知键(顶层、`components`、`botd` 或 `integrity`
内)、类型错误、缺少必填字段或 JSON 格式错误均为 `400`;非 JSON 的 content type 为 `415`。

### GET /challenge

```
200: {
  nonce: string,      // 一次性,服务端签发
  expires_in: number  // 秒(FP_NONCE_TTL_SECS,默认 30)
}
```

### POST /identify

```
Req: {
  nonce: string,                // 来自 GET /challenge,仅可使用一次
  ts: number,                   // 客户端 Unix 毫秒,必填,须在 ±FP_TS_SKEW_SECS 内
  components: { ... },          // 仅封闭 schema 键(fuzzy-matching §2)
  user_agent?: string,          // 客户端上报的 UA,顶层
  botd?: { bot: boolean, kind?: string },
  integrity?: {                 // 每个键均可选
    canvas?: "ok" | "noise" | "unavailable",
    webgl?: ..., audio?: ..., rect?: ...
  }
}
200: {
  request_id: string,           // 随机 128 位,32 位小写 hex
  visitor_id: string,           // 随机 128 位,32 位小写 hex
  confidence: 0.0..1.0,         // 判定置信度,不是身份可信度 —— 见 §6
  decision: "match" | "review" | "new_device",
  is_new_device: boolean,
  collision_risk: boolean,
  signals: {                    // 供风控引擎使用;原始被动信号从不回显
    ua_tls_consistent: boolean,
    ip_risk: "low" | "medium" | "high",
    client_integrity: "ok" | "noise" | "unavailable",
    persona_coherence: "consistent" | "mismatch" | "unknown",
    new_device_velocity: "low" | "medium" | "high",
    automation: "detected" | "not_detected" | "unknown",
    template_jump: boolean
  }
}
400: 未知键 / 类型错误 / JSON 格式错误
401: 未知、过期或复用的 nonce,或 ts 超出窗口
```

被动信号(JA4/IP)取自连接(§4.2),**从不**接受请求体中的值。所有 signals 都不会改变
`visitor_id` 或判定。

**`visitor_id`。** 随机 128 位 id,32 位小写 hex 字符,在判定为 `new_device` 时由宿主
铸造(原生:操作系统 RNG;边缘:`crypto.getRandomValues`)。它从不由分量派生。若铸造的 id
与存活或已擦除的访客重名则重新抽取,因此已擦除的访客永远不会拿回其 id。`request_id` 以同样
方式在每次成功的 identify 时铸造。

**`new_device_velocity`** 是以 IP 为键的**跨会话**信号。当判定为 `new_device` 且已知可信的
客户端 IP(§4.2)时,铸造的 `visitor_id` 会记录到该 IP 名下,并对尾随 1 小时窗口内为其铸造的
**不同** `visitor_id` 数量分级:≥ 5 为 `medium`,≥ 20 为 `high`(调参占位值)。`high`
等级在两个栈上都从 `confidence` 中减去 0.3;id 与判定不变。match、review 或没有可信客户端 IP
的请求为 `low`。它能发现任何单个请求都暴露不了的"每次启动换新种子"的设备农场。

**`client_integrity`** 融合 SDK 的四个**已知答案完整性探针**:采集器向浏览器提出未经修改的
Chromium 会精确作答的问题(不透明像素的无损 canvas `toDataURL` → `getImageData` 往返、
纯色 WebGL clear、离线渲染的 `ConstantSourceNode`、在 1/64 像素可表示偏移处的
`getBoundingClientRect`),并逐个探针报告 `ok` / `noise` / `unavailable`。加噪指纹
(反检测)浏览器会答错。这些判定位于请求顶层 —— 从不在 `components` 内 —— 因此无法进入
`visitor_id`;任一 `noise` 胜出,否则任一 `ok`,否则 `unavailable`(字段缺失或 API 缺失 ——
始终中性)。该等级**默认仅暴露**:合法的隐私工具(Brave farbling、canvas 拦截器)会触发同样
的探针,因此 `noise` 降权(−0.3)需显式开启(`integrity_penalty_enabled` /
`FP_INTEGRITY_PENALTY_ENABLED`)。

**`persona_coherence`** 把 UA 声称的操作系统家族(取自顶层 `user_agent`)与采集到的
`fonts` 集合交叉校验:Windows(`Windows NT`)或 macOS(`Macintosh`)UA 的字体集合中
**不含**该系统的任何核心字体(取自 FingerprintJS 探测列表的一份极小精选清单 —— Calibri、
Segoe UI Light、MS UI Gothic、Marlett、Microsoft Uighur / Helvetica Neue、Menlo、
Gill Sans)时为 `mismatch` —— 借用的 persona,例如在 Linux 容器里伪装 Windows 的伪装浏览器。
其他系统家族、缺少 `user_agent` 或缺少 `fonts` 分量时为 `unknown`。仅暴露。坦白的局限:
安装了 Windows 字体集(或伪造字体度量的二进制)的操作者可以通过;它只抬高成本。

**`automation`** 是客户端 BotD 判定(`bot: true` ⇒ `detected`,`false` ⇒
`not_detected`,缺失 ⇒ `unknown`)。仅暴露。

**`template_jump`** 为 `true` 表示最佳候选越过了匹配阈值,但 probe 改变了其模板过多的
高稳定分量;判定降级为 `review`,模板不更新
([fuzzy-matching §7](#7-漂移模板自适应与投毒防护))。

### GET /events/{request_id}

服务端到服务端读取过往 identify 结果。

```
Authorization: Bearer <FP_API_KEY>
200: 以 request_id 存储的 /identify 响应原文
401: 缺少或错误的 bearer
404: 未设置 FP_API_KEY(路由禁用),或 request_id 未知 / 已过期
```

设置 `FP_API_KEY` 时,每次成功的 `/identify` 都会把其响应体逐字节存储在其 `request_id`
下,保留 `FP_EVENT_TTL_SECS`(默认 3600 秒);未设置时不存储任何内容。原生存储在内存中,
受 `FP_EVENT_MAX`(默认 100 000;超出后淘汰最旧事件)约束;边缘把事件存在 `events` 表中。

**信任链。** 浏览器收到的 `/identify` 响应**仅供展示**:页面中运行的任何代码都能改写它。
浏览器只把 `request_id` 转交给客户后端,由后端通过 `GET /events/{request_id}` 以服务端到
服务端方式取回权威结果(或在边缘上把 `request_id` 交给 `POST /checkin/assess`)。
`FP_API_KEY` 是服务端密钥,绝不能下发到浏览器。

### DELETE /visitor/{id}

GDPR 被遗忘权(§7)。

```
Authorization: Bearer <FP_ADMIN_KEY>
204: 已擦除(幂等 —— 未知 id 也返回 204,从不泄露是否存在)
401: 缺少或错误的 bearer
404: 未设置 FP_ADMIN_KEY(路由禁用)
```

擦除会删除该访客的模板、其 blocking 索引成员关系以及该访客的所有已存 identify 事件(于是
`GET /events/{request_id}` 随后对它们返回 `404`),并对该 id 写入墓碑,使其永不再被铸造或写入(原生:
最多 100 000 个 id 的内存墓碑集合;边缘:`erased_visitors` 表,修剪为最新的 100 000 条)。

### POST /checkin/assess(仅边缘)

每日签到防薅的参考风控消费方,仅由边缘 Worker 提供。

```
Authorization: Bearer <FP_API_KEY>
Req: { account_id: string, action: "daily_checkin", request_id: string }
200: {
  decision: "allow" | "challenge" | "deny",
  verdict: "human" | "suspicious" | "farming",
  risk: number,
  reasons: [{ code: string, detail: string }],
  visitor_id: string
}
401: 缺少或错误的 bearer
404: 未设置 FP_API_KEY(路由禁用),或 request_id 未知 / 已过期
409: 该 request_id 已为另一个 account_id 评估过
```

设备 id、signals 与客户端 IP 全部来自已存储的 identify 事件(服务端查找),从不来自调用方。
每个 `request_id` 只记录一次签到;同账号重试是幂等的(`200`);`409` 不打分也不记录。

### 负载限制与状态码汇总

原生服务器让所有路由运行在全局并发上限(`FP_MAX_CONCURRENT_REQUESTS`,默认 1024;
其余请求等待空位)和单请求截止时间(`FP_REQUEST_TIMEOUT_SECS`,默认 10 秒,含等待时间)
之下,超时返回 `408`。边缘按 `cf-connecting-ip` 做逐 IP 限流:`RATE_LIMIT`(60 / 60 秒)
作用于 `POST /identify` 与 `POST /checkin/assess`,`CHALLENGE_RATE_LIMIT`
(120 / 60 秒)作用于 `GET /challenge`,超出返回 `429`。

| 状态码 | 场景 |
|---|---|
| `400` | 请求体任意位置出现未知键或类型错误的值;JSON 格式错误 |
| `401` | `/identify`:nonce 错误、过期或复用,或 `ts` 超出窗口。密钥门控路由:缺少或错误的 bearer |
| `404` | `/events`、`/checkin/assess`:未设置 `FP_API_KEY`,或 `request_id` 未知/已过期。`/visitor`:未设置 `FP_ADMIN_KEY` |
| `408` | 原生:请求未在 `FP_REQUEST_TIMEOUT_SECS` 内得到响应 |
| `409` | 边缘 `/checkin/assess`:`request_id` 已为另一个 `account_id` 评估过 |
| `415` | `POST` 请求体不是 JSON |
| `429` | 边缘:超出逐 IP 限流 |

---

## 6. 数据模型

宿主只持久化设备的加盐存储形式,从不持久化原始分量值
(§7,[fuzzy-matching §3](#3-存储表示加盐存储形式))。

**原生服务器** —— 全部在内存中、进程本地且有界:

- **nonces** —— 存活 nonce 及其过期时间,一次性,过期回收;最多 `FP_NONCE_MAX_LIVE`
  (默认 1 000 000),超出后淘汰最旧的。
- **模糊存储** —— 记录库(`visitor_id` → 当前存储模板、首次观测快照、逐分量新鲜度、
  首次/最近出现时间、观测次数、blocking 键)、blocking 索引、逐分量频率表(`u_i`)、
  一致性表(`m_i`)、逐 IP 速度表以及擦除墓碑。上限:`FP_FUZZY_MAX_RECORDS`、
  `FP_FUZZY_RECORD_TTL_SECS`、`FP_FUZZY_MAX_BLOCK`、
  `FP_FUZZY_MAX_FREQUENCY_VALUES`、`FP_FUZZY_MAX_AGREEMENT_COMPONENTS`
  ([fuzzy-matching §11](#11-数据结构与性能))。
- **events** —— `request_id` → identify 响应体,TTL `FP_EVENT_TTL_SECS`,上限
  `FP_EVENT_MAX`,按 `visitor_id` 建索引以便擦除。

**边缘 Worker** —— 两个 Durable Object 加一个由 `DB_TYPE` 选定的 SQL 数据库:
`libsql`(默认;`LIBSQL_URL` + 可选的 `LIBSQL_AUTH_TOKEN`)或 `d1`(`DB` 绑定):

- `NONCE` Durable Object —— 一次性 nonce(原子的检查并销毁 + TTL alarm)。
- `VELOCITY` Durable Object —— 逐 IP 的不同新设备 id(1 小时窗口,最多 64 个存活成员)。
- `templates` —— `visitor_id`、加盐存储形式(`stored`)、`first_seen`、`last_seen`、
  `observation_count`。
- `blocking_index` —— 倒排索引的 `(key, visitor_id)` 行。
- `erased_visitors` —— 擦除墓碑。
- `events` —— `request_id`、`visitor_id`、客户端 `ip`、响应 `body`、`expires_at`。
- `checkin_events` —— 只追加的签到日志,按 `request_id` 唯一。

**`confidence` 语义。** `confidence` 是**判定置信度**,不是身份可信度:首次出现的未知设备
会以较高的判定置信度解析为 `new_device`(引擎确信它是新的)。风控消费方必须读取
`is_new_device` / `decision` 判断身份可信度,不得把高置信的 `new_device` 当作高可信身份。

---

## 7. 隐私与合规

存储派生指纹比纯客户端方案敏感度更高,因此:

- **法律依据** —— 在 GDPR/CCPA/PIPL 下设备指纹通常属于个人数据;反欺诈通常基于正当利益,
  这需要 DPIA 记录。
- **数据最小化** —— 宿主只持久化加盐存储形式:category 值为 `SHA-256(salt ‖ value)`,
  set 值为逐元素 `SHA-256(salt ‖ element)`,numeric 值(`cpu_cores`、`device_memory`)
  为整数。盐按实例区分 —— 原生服务器为 16 个随机字节,边缘为 `SHA-256(FP_SALT_SECRET)`
  的前 16 字节([fuzzy-matching §3](#3-存储表示加盐存储形式))。`user_agent`、`botd` 与
  `integrity` 输入从不持久化;已存事件保存 identify 响应(在边缘还保存客户端 IP)。
- **保留期限** —— 原生:`FP_RETENTION_SECS`(默认 `0` = 关闭)运行后台清扫,按
  `last_seen` 清除记录;`FP_FUZZY_RECORD_TTL_SECS` 在 identify 时惰性淘汰。边缘:每日
  cron(UTC 03:00)删除过期事件、超过 `FP_RETENTION_SECS` 的模板(随附的
  `wrangler.jsonc` 设为 30 天)、超过 `CHECKIN_RETENTION_SECS` 的签到事件,并修剪墓碑。
  两端事件均在 `FP_EVENT_TTL_SECS` 后过期。
- **擦除** —— `DELETE /visitor/{id}`(§5)删除模板、索引行与事件,并为该 id 写入墓碑。
  聚合频率表保持不变:它只保存值计数,不与具体访客关联。
- **严格输入** —— 封闭的请求 schema 以 `400` 拒绝未建模字段。
- **目的限制** —— 仅用于反欺诈;用于广告/追踪会改变法律依据,不在范围内。
- **透明度** —— 在隐私政策中披露设备指纹。

---

## 8. 部署目标

一个引擎([`crates/fp-core`](crates/fp-core),即发布的 `fingerprintd` crate),两个宿主。
客户端无需修改即可对接任一宿主;共享的一致性样例
(`crates/fingerprintd/tests/fixtures/parity.json`)在两端都被断言。

| 关注点 | 原生服务器(`crates/fingerprintd`,包 `fingerprintd-server`,二进制 `fingerprintd`) | 边缘 Worker(`apps/edge`,演示) |
|---|---|---|
| 运行时 | Axum / Tokio,常驻进程,收到 SIGTERM / Ctrl-C 时优雅停机 | Cloudflare Worker(Hono 宿主,按请求) |
| Nonce 存储 | 内存,一次性 + TTL,有界 | `NONCE` Durable Object |
| 指纹库 | 内存模糊存储,有界/可淘汰 | libSQL(默认)或 D1:`templates` + `blocking_index` |
| 事件 | 内存,TTL + 上限 | `events` 表 |
| 计算 | 原生 `fingerprintd` | 编译为 WASM 的 `fingerprintd`(`crates/fp-wasm`,不发布) |
| 被动信号 | `trust_edge_headers` 之后的 Cloudflare 请求头(§4.2) | `request.cf` + `cf-connecting-ip`,外加 ASN 融合 |
| 配置 | 默认值 ← `fingerprintd.toml` ← `FP_*` 环境变量 | Worker vars / secrets(`FP_SALT_SECRET` 必填) |

原生存储是进程本地的,其盐按进程随机生成:重启会丢失所有模板并重新铸造设备。持久化部署见
[`apps/edge`](apps/edge/README.md)。

**边缘已知局限。**

- **并发首次出现。** 没有逐设备锁:同一设备的两次并发首次 identify 可能各自铸造一个
  `visitor_id`。(原生存储在写锁下重新判定,因此并发首次出现只产生一个访客。)
- **冷启动打分存储。** 边缘每个请求都从召回的候选重建打分存储,因此 `m_i` 停留在冷启动先验,
  `u_i` 只在召回的块上估计。多次确认匹配后,原生与边缘的 `confidence` 可能出现偏差;身份与
  判定由同一引擎计算。
- **有界召回。** 召回先访问精确键,再按最稀有的键依次访问,每个键最多取 256 个访客(最近
  出现者优先),总计最多 1024 个。极热的块仍可能漏掉真实匹配。
- **无首次观测快照。** `templates` 只保存当前漂移后的模板。

**下游消费方。** `visitor_id` + `confidence` + `signals` 是*供风控引擎使用*的输入,本身
不是裁决 —— 核心不保存账号状态,也不保存行为历史(非目标,§2)。需要 allow/challenge/deny
决策的调用方在其上叠加。边缘附带一个参考示例 `POST /checkin/assess`(§5):它把已存的
identify 事件与按窗口聚合的账号/设备/IP/时间统计(设备扇出、账号设备数、新设备率、IP 共享、
时间规律性)结合,为每日签到防薅打分。[playground](apps/web/README.md) 演示了
identify → assess 流程。

---

## 9. 纵深防御控制

| 控制 | 设置 | 默认值 |
|---|---|---|
| 一次性 nonce | `FP_NONCE_TTL_SECS` | 30 秒 |
| 时间戳窗口(始终强制) | `FP_TS_SKEW_SECS` | ±30 秒 |
| 信任 Cloudflare 被动信号请求头(原生) | `trust_edge_headers` / `FP_TRUST_EDGE_HEADERS` | `false`(fail-closed) |
| 完整性 `noise` 置信度惩罚 | `integrity_penalty_enabled` / `FP_INTEGRITY_PENALTY_ENABLED` | `false`(显式开启;始终暴露) |
| 事件 API + 签到 | `api_key` / `FP_API_KEY` | 未设置 ⇒ `404` |
| 擦除 | `admin_key` / `FP_ADMIN_KEY` | 未设置 ⇒ `404` |
| 保留期清扫 | `retention_secs` / `FP_RETENTION_SECS` | `0`(关闭);边缘配置随附 30 天 |
| 请求截止时间(原生) | `FP_REQUEST_TIMEOUT_SECS` | 10 秒 ⇒ `408` |
| 并发上限(原生) | `FP_MAX_CONCURRENT_REQUESTS` | 1024 |
| 逐 IP 限流(边缘) | `RATE_LIMIT` / `CHALLENGE_RATE_LIMIT` | 60 / 60 秒、120 / 60 秒 ⇒ `429` |
| 有界存储(原生) | `FP_NONCE_MAX_LIVE`、`FP_EVENT_MAX`、`FP_FUZZY_MAX_*` | 见 §6 |

密钥门控路由是 fail-closed 的:未设置或为空的密钥会禁用路由,bearer 以常数时间比较。
密钥在调试输出中被脱敏。模板跳变防护与 review 不更新规则
([fuzzy-matching §7](#7-漂移模板自适应与投毒防护))保护指纹库免遭投毒。客户端证据只是纵深,
从不作为锁。

---

# 模糊匹配

> [architecture §4.3](#43-模糊匹配与候选生成) 背后的阶段二匹配引擎。
> 目标([architecture §3](#3-成功指标)):稳定率 ≥ 95%,碰撞率 ≤ 1%,
> 判定 P99 ≤ 50ms,单实例 ≥ 2k RPS。

## 1. 问题定义

输入:一次观测的分量集合 `probe = {c_1, …, c_n}`。
输出:匹配到的 `visitor_id`(同一设备)或新设备判定,外加一个 `confidence`。

三个约束相互牵制:

- **去雪崩** —— 单个分量变化(浏览器自动升级、新字体、外接显示器)不得铸造新的
  `visitor_id`。
- **防碰撞** —— 同型号 + 同浏览器版本的两台不同设备不得解析为同一 `visitor_id`。
- **高吞吐** —— 不能对百万级指纹库逐请求线性扫描。

两个核心决策:

1. **两阶段** —— 候选生成(§4)→ 概率打分(§5)。
2. **打分采用 Fellegi–Sunter(FS)概率记录链接模型**(§5),而非手调加权平均 —— FS 的
   两个参数 `m_i / u_i` 分别建模*稳定性*与*区分度*,天然对应上述两种失败模式。

---

## 2. 分量分类(封闭 schema)

每个分量在两个正交维度上刻画 —— 这是所有权重的来源:

- **稳定性** —— 同一设备多次访问时该分量不变的概率(→ FS `m_i`;冷启动先验 high `0.95`、
  medium `0.80`、low `0.50`)。
- **区分度** —— 两台不同设备共享该值的概率(→ FS `u_i`;越稀有 `u` 越低)。

schema 是封闭的:以下 18 个键(`crates/fp-core/src/fuzzy/component.rs` 中的
`COMPONENT_KEYS`)是 `components` 唯一接受的键;任何其他键都是 `400`。`null` 或缺失的键
表示"未采集"。

| 键 | 类型 | 稳定性 | `u_i` 先验 | 说明 |
|---|---|---|---|---|
| `webgl` | category | high | 0.05 | GPU vendor/renderer |
| `webgl_extensions` | category | medium | 0.05 | 支持扩展的摘要 |
| `platform` | category | high | 0.3 | `navigator.platform` |
| `timezone` | category | high | 0.2 | IANA 名称 |
| `languages` | category | high | 0.3 | 逗号拼接 |
| `audio` | category | high | 0.05 | 音频栈渲染指纹 |
| `canvas` | category | low | 0.02 | 驱动/浏览器升级时整体翻转;被隐私 / 反检测浏览器按会话加噪 |
| `cpu_cores` | numeric | high | 0.3 | |
| `device_memory` | numeric | high | 0.4 | GiB |
| `screen` | category | medium | 0.1 | `"WxH"`,长边在前;外接显示器会改变它 |
| `fonts` | set | medium | 0.05 | 增量变化 → Jaccard / MinHash |
| `plugins` | set | medium | 0.3 | 插件名 |
| `font_preferences` | category | medium | 0.1 | |
| `screen_frame` | category | medium | 0.2 | 任务栏/程序坞内边距 |
| `math` | category | medium | 0.5 | |
| `touch_support` | category | medium | 0.5 | |
| `dom_blockers` | category | medium | 0.5 | 内容拦截器检测 |
| `user_agent_data` | category | medium | 0.05 | UA Client Hints 摘要 |

`u_i` 先验是调参占位值(判断所得,非测量)。

> 关键洞察:浏览器版本字符串不是分量。UA 只作为顶层 `user_agent` 传递(UA↔TLS 与
> persona 检查),因此浏览器自动升级无法借它让身份雪崩;确实会随升级变化的分量(`canvas`、
> medium 档)`m_i` 较低,不一致只带来有界的扣分。

---

## 3. 存储表示(加盐存储形式)

为满足数据最小化([architecture §7](#7-隐私与合规)),在保留匹配能力的同时从不存储原始值。
每个宿主只持久化**加盐存储形式**(`StoredComponents`):以分量名为键的 JSON 对象,缺失的
分量被省略。

- **Category** —— `{"category": "<64 hex>"}`,加盐哈希 `SHA-256(salt ‖ value)`。支持
  相等比较 + 频率计数(用于 `u_i`)。
- **Set**(`fonts`、`plugins`)—— `{"set": ["<64 hex>", …]}`,排序后的**逐元素**加盐
  哈希。逐元素哈希**保留 Jaccard**,因此集合相似度 + MinHash 仍然可用。
- **Numeric**(`cpu_cores`、`device_memory`)—— `{"numeric": <i64>}`,JSON 数值四舍五入
  到最近的整数。

反序列化会拒绝未知分量名、类型错误的值或格式错误的哈希。盐是 16 字节的逐实例密钥:原生服务器
上随机生成,边缘上取 `SHA-256(FP_SALT_SECRET)` 的前 16 字节,使每个 isolate 推导出相同的
哈希与 blocking 键。对每个 `visitor_id`,原生指纹库还保存首次观测快照、逐分量新鲜度、
`first_seen`、`last_seen` 与 `observation_count`(§7、§11)。

---

## 4. 阶段一:候选集生成(blocking)

目标:从百万级指纹库中以近 O(1) 得到有界的候选集,**且不漏掉真实匹配**(召回优先)。

不能用单一精确键 —— 任一分量变化就会漏召。使用**多个独立 blocking 键取并集**实现召回冗余
(每个键都是对加盐存储值的 SHA-256;组合键仅在其所有成员都存在时才生成):

- `K0` —— 所有存在的标量(category + numeric)分量的名称与值:精确匹配键,刻意脆弱
- `K1 = H(webgl ‖ platform ‖ timezone)` —— 一个高稳定子集
- `K2 = H(audio ‖ cpu_cores ‖ device_memory)` —— 另一个不相交的高稳定子集
- `K3` —— 对 `fonts` 集合的 MinHash-LSH band 键(16 个置换,8 个 band × 2 行),
  容忍字体增量变化

召回率 = 1 − P(所有键都未命中)。每个键使用不同的分量子集,因此一个分量变化时另一个键仍能
命中。候选集 = ∪(各键命中的 `visitor_id`)。

**索引** —— 一个 `blocking_key → set<visitor_id>` 倒排索引同时容纳标量键与 MinHash
band 键。

**热块膨胀** —— 流行配置(默认 Safari 的 iPhone)会让某个块巨大(信息量低)。缓解:

- 限制块大小(原生 `FP_FUZZY_MAX_BLOCK`,默认 1024);超过上限的键信息量很低,无法收窄候选
  —— 由阶段二打分(§5)消歧;
- 超限丢弃会被计数并记录日志(不静默截断),杜绝"看似覆盖实则没有"的情况;
- 边缘改为在每个请求内限制召回:先精确键,再最稀有的键,每个键最多 256 个访客,总计最多 1024 个。

---

## 5. 阶段二:概率打分(Fellegi–Sunter)

对每个候选 `cand` 与 `probe` 逐分量比较,累加对数似然比。

### 5.1 逐分量一致性 `agree_i`

- Category —— 哈希相等 → 一致,否则不一致。
- Set —— Jaccard `J = |A∩B| / |A∪B|`;`J ≥ τ` → 完全一致(`τ = 0.5`),否则一致比例为
  `J`(见 5.3)。
- Numeric —— 整数相等 → 一致,否则不一致。

### 5.2 两个参数

- `m_i = P(agree_i | 同一设备)` —— 建模稳定性;从 §2 的档位先验出发,由**确认匹配**修正(§9)。
- `u_i = P(agree_i | 不同设备)` —— 建模区分度;由 probe 的值在该分量所有出现中的**频率**
  估计(§9)。稀有值 → `u_i` 很低 → 相等是强证据;常见的 Chrome/Windows 值 → `u_i` 高 →
  相等几乎不加分。

### 5.3 逐分量权重

```
u_i ← min(u_i, m_i)                                      // 比稳定更常见的值不构成证据
agree:      w_i = log2( m_i / u_i )                      // 正;越稀有越大
disagree:   w_i = log2( (1 - m_i) / (1 - u_i) )          // 负;越稳定越负
partial (set, J < τ): w_i = J · log2(m_i/u_i) + (1-J) · log2((1-m_i)/(1-u_i))
missing (任一侧缺失): w_i = 0                             // 不比较、不计分(见 §8)
```

总分:`score(cand) = Σ_i w_i`,单位为 bit。

**为什么模型是对的:**

- **去雪崩** —— 低 `m_i` 的分量(canvas)不一致时 `(1-m_i)/(1-u_i)` 接近 1,其 `log`
  很小 → 几乎不扣分。
- **防碰撞** —— 两台同型号设备在高稳定分量上不一致,这些分量 `m_i` 高 → 每个不一致都带来
  很大的负值,把总分拉到阈值以下 → 判为不同设备。
- **低熵自动淡化** —— 常见值的 `u_i` 高(以 `m_i` 为上限)→ 一致几乎不加分,因此"同在一个
  时区"永远不会强行匹配。

### 5.4 判定

取最高分候选 `best`;两个阈值 `T_hi = 12` bit > `T_lo = 8` bit:

- `score(best) ≥ T_hi` → **同一设备**(`match`);返回其 `visitor_id`,应用漂移(§7)——
  除非模板跳变防护(§7)把它降级为 `review`。
- `T_lo ≤ score(best) < T_hi` → **疑似**(`review`);返回该 `visitor_id` 并降低置信度;
  不写入任何内容。
- `score(best) < T_lo`(或没有候选)→ **新设备**(`new_device`);宿主铸造新的
  `visitor_id`。
- **match 的次优候选同样 ≥ `T_hi` 且差距在 2 bit 以内** → 碰撞风险;取最高分并设置
  `collision_risk`。

---

## 6. confidence 输出

`confidence ∈ [0,1]`,按规则加权(无学习模型)。引擎依据判定、分数间距与完整度计算基础值:

- **Match** —— `0.5 + 0.5 · min(σ((s − T_hi)/4), σ((s − s₂)/4))`:`score(best)` 超出
  `T_hi` 的幅度及其与次优 `s₂` 的差距(σ 为 logistic 函数;没有次优时视为差距饱和)。
- **Review** —— `0.25 + 0.25 · (s − T_lo)/(T_hi − T_lo)`。
- **New device** —— `0.5 + 0.5 · (1 − σ((s − T_lo)/4))`:最佳分远低于 `T_lo` 时确信它是新的。
- **完整度** —— 基础值乘以 `0.5 + 0.5 · min(compared / 8, 1)`,其中 `compared` 是与最佳
  候选参与打分的分量数;缺失越多 → 置信度越低(§8)。

随后由宿主融合,每一步后都裁剪到 `[0, 1]`:

- **新设备速度** —— 等级为 `high` 时 `−0.3`([architecture §5](#5-http-接口contract-v1))。
- **被动信号一致性** —— UA/JA4 一致 → `+0.05`;不一致 → `−0.5`(防伪造的核心,
  [architecture §4.2](#42-被动信号与信任边界));降级 → `0`。
- **客户端完整性** —— `noise` 时 `−0.3`,仅在开启 `integrity_penalty_enabled` 时。

---

## 7. 漂移(模板自适应)与投毒防护

没有漂移的话,存储的分量会过时,几次浏览器升级后匹配就会退化。规则:

- **只有确认的 `match`** 才更新模板:probe 中出现的每个分量覆盖模板的值与新鲜度,
  `last_seen` 与 `observation_count` 前进,blocking 成员关系按合并后的模板重新推导。在边缘上,
  合并后的存储形式写回 `templates`。
- **`review` 不写入任何内容** —— 既不写模板,也不写任何估计材料。
- **模板跳变防护。** 最佳候选越过 `T_hi`,但 probe 改变了被匹配模板中**超过 2 个**高稳定
  分量(`webgl`、`platform`、`timezone`、`languages`、`audio`、`cpu_cores`、
  `device_memory`;只计两侧都存在的分量)时,降级为 `review` 并设置
  `signals.template_jump: true`,模板不更新。这限制了单次观测能把模板推移多远,阻止攻击者把
  一台设备的模板逐步走到另一台设备上。
- **不可变的起点。** 原生记录保存创建它的那次观测的存储值(`first_observation`);漂移从不
  覆盖它,因此无论模板漂移多远,其起点都可审计。

---

## 8. 边界情况

- **隐私浏览器拦截 canvas(null/空)** —— 缺失分量记 `w_i = 0`,不参与打分。绝不能把
  "null canvas"当作可匹配的值 —— 否则所有隐私用户在该分量上都一致 → 大规模碰撞。缺失越多 →
  置信度越低。
- **Brave 式按会话随机化 canvas** —— 同一设备每次访问该分量都会变;canvas 位于 low 档
  (`m_i` 先验 0.5),因此其不一致权重很小,匹配回落到 fonts/audio/webgl。
- **企业黄金镜像 / 完全相同的虚拟机** —— 真正不同的设备拥有相同指纹;模糊匹配无法区分,必然
  碰撞。必须回落到 IP + 账号行为;这是**已知能力边界**,本引擎不解决。

---

## 9. 参数估计与冷启动

- `u_i` —— 逐分量的值频率,在存储中增量更新。计数以 `(component, value hash)` 为键,
  分母**按分量**独立(set 通过与顺序无关的摘要作为整体计数),并且统计的是**设备而非访问**
  (回访只计入发生变化的值)。估计值为 `(hits + 10 · u_prior) / (total + 10)`,裁剪到
  `[1e-4, 0.9999]`:逐分量先验(§2)让冷启动或很小的库(边缘只在召回块上打分)保持在先验附近,
  随着出现次数累积由观测频率接管。权重把 `u_i` 上限设为 `m_i`(§5.3)。
- `m_i` —— 由确认匹配在线学习:每次 `match` 时,在漂移之前,两侧都存在的每个分量记录一次
  同设备观测(相似度越过 `τ` 即为一致)。估计值为 `(agree + 20 · prior) / (total + 20)`,
  裁剪到 `[1e-4, 0.9999]`;没有观测时**精确**等于 §2 的先验。边缘不保存一致性材料,因此其
  `m_i` 停留在先验([architecture §8](#8-部署目标))。
- 冷库阶段:一切都读作新设备;blocking 索引与频率统计随时间累积。

---

## 10. 离线评估

证明 architecture §3 的目标首先需要一个标注评估集:

- **真值** —— 用登录态 / 长效 cookie 标注"同一设备的多次访问"。
- **稳定率** —— 同设备回访被解析为同一 `visitor_id` 的比例(扫描 `T_hi`)。
- **碰撞率** —— 不同设备被解析为同一 `visitor_id` 的比例。
- 网格搜索 `T_lo / T_hi / τ` 及分量先验;绘制稳定率–碰撞率权衡曲线来设定阈值。
- 上线后持续把 review/collision_risk 样本回送人工复核,以修正 `m_i/u_i` 与阈值。

> 仓库附带一个合成样例和回放工具
> (`cargo run -p fingerprintd-server --example eval`),用于**方向性**地检验打分接线 ——
> 这是冒烟测试,不是数值目标的证据。它打印的比率不得作为生产稳定率/碰撞率报告。

---

## 11. 数据结构与性能

| 用途 | 结构 | 原生 | 边缘 |
|---|---|---|---|
| Blocking 倒排索引 | `key → set<visitor_id>` | 内存,单块上限 `FP_FUZZY_MAX_BLOCK`(1024) | `blocking_index` 表 |
| MinHash-LSH | blocking 索引中的 band 键 | 16 个置换,8 个 band × 2 行 | 相同(以 `FP_SALT_SECRET` 为种子) |
| 指纹库 | `visitor_id → record` | 当前模板 + 首次观测 + 新鲜度 + 时间戳 + 键;上限 `FP_FUZZY_MAX_RECORDS`(1 000 000),淘汰最旧 `last_seen`;可选 TTL | `templates` 表(当前模板 + 时间戳) |
| 频率统计 | `(component, value hash) → count` + 逐分量总数 | 上限 `FP_FUZZY_MAX_FREQUENCY_VALUES`(1 000 000) | 每个请求从召回模板重建 |
| 一致性统计 | `component → (agree, total)` | 上限 `FP_FUZZY_MAX_AGREEMENT_COMPONENTS`(1024) | 无(先验) |
| 速度 | `ip → {visitor_id → last seen}` | 1 小时窗口,每 IP ≤ 64 个 id,≤ 1 000 000 个 IP | `VELOCITY` Durable Object |
| 墓碑 | 已擦除的 `visitor_id` | FIFO,100 000 | `erased_visitors`,修剪至 100 000 |

每一次因上限导致的淘汰或丢弃都会计数,从不静默。性能:阶段一为 O(候选数);阶段二为
O(候选数 × 常数个分量)。在原生服务器上,所有匹配状态位于一把读写锁之后:召回与打分在共享读锁
下进行,写回获取独占锁;若期间状态发生变化,则在持久化任何内容之前针对写锁下的状态重新判定,
因此同一设备的并发首次出现只产生一个访客,与擦除竞争的 identify 也绝不会复活已擦除的 id。
匹配运行在阻塞线程池上,不占用异步 worker。

---

## 12. 待解决问题

1. set 分量的 MinHash band 数 / τ —— 需要真实数据测量。
2. `m_i` 收敛需要多少确认的同设备回访,以及伪计数权重(`u_i` 为 `10`,`m_i` 为 `20`)。
3. 块大小上限,以及超限群体的回退方案(强制要求高熵一致?)。
4. 频率统计的时间衰减窗口(对陈旧值降权?)。
5. 是否按设备群体分层估计参数(移动端与桌面端的 `m/u` 不同)。
6. 识别 canvas 始终变化的群体并对其屏蔽该分量。
7. 在边缘持久化频率与一致性材料,使其 `confidence` 与原生收敛。
