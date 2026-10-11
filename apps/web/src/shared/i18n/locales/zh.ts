// Chinese translations keyed by the source English string (natural-language
// keys). English is the source language, so only this map is needed.
export const zh: Record<string, string> = {
  // Chrome
  Language: '语言',
  Light: '浅色',
  Dark: '深色',
  System: '跟随系统',
  Theme: '主题',

  // Page
  'Challenge / identify playground': 'Challenge / identify 调试台',
  'Run the collect-only client flow against a fingerprintd server and inspect what it sends and what the server judges.':
    '对 fingerprintd 服务端运行「仅采集」的客户端流程，查看它提交了什么、服务端如何判定。',

  // Run panel
  'Server base URL': '服务端 Base URL',
  'Signing key (optional)': '签名密钥（可选）',
  'UTF-8 signing key to verify the response signature':
    '用于校验响应签名的 UTF-8 密钥',
  'Account ID': '账户 ID',
  'Business account to score for check-in farming after identify succeeds.':
    'identify 成功后，用于评估签到刷量风险的业务账户。',
  'Run flow': '运行流程',
  'Running…': '运行中…',
  Reset: '重置',
  'Enter a server base URL first.': '请先填写服务端 Base URL。',
  'Flow failed': '流程失败',

  // Challenge
  Challenge: '挑战',
  nonce: 'nonce',
  'expires in': '有效期',
  targets: '采集目标',
  seconds: '秒',

  // Identity
  Identity: '身份',
  Confidence: '置信度',
  Decision: '判定',
  'New device': '新设备',
  'Collision risk': '碰撞风险',
  Signals: '信号',
  'UA / TLS consistent': 'UA / TLS 一致',
  'IP risk': 'IP 风险',
  'Client integrity': '客户端完整性',
  'Persona coherence': '人设一致性',
  'known-answer probe verdicts (canvas / webgl / audio / rect) — a risk signal, never matching input':
    '已知答案探针判定（canvas / webgl / audio / rect）—— 风险信号，绝不参与匹配',
  Yes: '是',
  No: '否',
  match: '匹配',
  review: '待审',
  new_device: '新设备',
  'Original fingerprint (client-side)': '原始指纹（客户端）',
  'FingerprintJS computes this hash in the browser. The SDK discards it — the server judges identity from raw evidence instead.':
    'FingerprintJS 在浏览器中计算出该哈希；SDK 会丢弃它 —— 改由服务端依据原始证据判定身份。',

  // Evidence lanes
  'Collected evidence': '采集到的证据',
  'Stable components': 'Stable components',
  'the "who is this device" matching input': '用于「这是哪台设备」匹配的输入',
  'Challenge response': 'Challenge response',
  'nonce-seeded freshness proof — never a matching signal':
    'nonce 播种的新鲜度证明 — 绝不作为匹配信号',
  Probe: 'Probe',
  'hex(HMAC-SHA256(key, nonce)) computed in WASM':
    '在 WASM 中计算的 hex(HMAC-SHA256(key, nonce))',
  'Timestamp (ts)': '时间戳 (ts)',
  'client clock at collection': '采集时的客户端时钟',
  'not sent': '未发送',

  // Check-in risk
  'Check-in risk': '签到风险',
  'Anti-farming decision for this account on daily_checkin.':
    '该账户在 daily_checkin 上的反刷量判定。',
  'Assessing check-in risk…': '正在评估签到风险…',
  'Check-in assessment unavailable': '签到评估不可用',
  Verdict: '判定',
  Risk: '风险',
  Reasons: '原因',
  'No reasons.': '无原因。',
  allow: '放行',
  challenge: '验证',
  deny: '拒绝',
  human: '真人',
  suspicious: '可疑',
  farming: '刷量',

  // Signature
  'Response signature': '响应签名',
  Signed: '已签名',
  Timestamp: '时间戳',
  Signature: '签名',
  Verified: '已校验',
  'not verified (no key)': '未校验（无密钥）',
  'Server did not sign this response.': '服务端未对此响应签名。',

  // Hero
  'challenge → identify': '挑战 → 识别',
  'Lift a device fingerprint,': '提取设备指纹，',
  'read the verdict.': '读取判定结果。',
  'Point the collect-only client at a fingerprintd server. It answers a nonce challenge, gathers stable device signals in WASM, and returns a signed match / review / new-device call.':
    '将「仅采集」客户端指向 fingerprintd 服务端：它应答 nonce 挑战，在 WASM 中采集稳定设备信号，并返回带签名的 匹配 / 待审 / 新设备 判定。',

  // Empty state
  'No run yet': '尚未运行',
  'Fill in a server base URL and run the flow to see the result here.':
    '填写服务端 Base URL 并运行流程，结果将显示在此处。',
  Collect: '采集',
  Identify: '识别',
  'Server issues a nonce and the list of signals to collect.':
    '服务端下发 nonce 与待采集的信号清单。',
  'Client gathers stable components and computes an HMAC probe in WASM.':
    '客户端采集稳定组件，并在 WASM 中计算 HMAC probe。',
  'Server judges the evidence and returns a verdict with confidence.':
    '服务端评判证据，返回带置信度的判定结果。',

  // Check-in decision-band examples
  'Check-in decision bands': '签到决策档位',
  'What the anti-farming layer decides': '反刷量层如何裁决',
  'Representative outcomes across the three decision bands — no live device farm required.':
    '覆盖三档决策的代表性结果 —— 无需真实设备农场即可查看。',
  'Returning human — allowed': '回访真人 —— 放行',
  'Device churn — challenged': '设备频繁更替 —— 验证',
  'Device farm — denied': '设备农场 —— 拒绝',
}
