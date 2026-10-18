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
  'Account ID': '账户 ID',
  'Business account your backend scores for check-in farming, used in the server-side check-in snippet.':
    '你的后端用于评估签到刷量风险的业务账户，用于下方的服务端签到示例。',
  'Run flow': '运行流程',
  'Running…': '运行中…',
  Reset: '重置',
  'Enter a server base URL first.': '请先填写服务端 Base URL。',
  'Flow failed': '流程失败',

  // Challenge
  Challenge: '挑战',
  nonce: 'nonce',
  'expires in': '有效期',
  seconds: '秒',

  // Identity
  Identity: '身份',
  Confidence: '置信度',
  'New device': '新设备',
  'Collision risk': '碰撞风险',
  'UA / TLS consistent': 'UA / TLS 一致',
  'IP risk': 'IP 风险',
  'Client integrity': '客户端完整性',
  'Persona coherence': '人设一致性',
  'New-device velocity': '新设备速率',
  Automation: '自动化',
  'Template jump': '模板跳变',
  'known-answer probe verdicts (canvas / webgl / audio / rect) — a risk signal, never matching input':
    '已知答案探针判定（canvas / webgl / audio / rect）—— 风险信号，绝不参与匹配',
  Yes: '是',
  No: '否',
  match: '匹配',
  review: '待审',
  new_device: '新设备',
  'Original fingerprint (client-side)': '原始指纹（客户端）',
  'FingerprintJS computes this hash in the browser. The SDK discards it — the server judges identity from raw evidence and returns visitor_id.':
    'FingerprintJS 在浏览器中计算出该哈希；SDK 会丢弃它 —— 改由服务端依据原始证据判定身份并返回 visitor_id。',

  // Evidence lanes
  'Collected evidence': '采集到的证据',
  'the "who is this device" matching input': '用于「这是哪台设备」匹配的输入',
  'browser user agent and client-side BotD verdict':
    '浏览器 User-Agent 与客户端 BotD 判定',
  'client clock when the request was sent': '发送请求时的客户端时钟',
  'not sent': '未发送',

  // Check-in risk
  'Check-in risk': '签到风险',
  'Anti-farming decision for this account on daily_checkin.':
    '该账户在 daily_checkin 上的反刷量判定。',
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

  // Server-side check-in
  'Server-side check-in': '服务端签到',
  'Send the request_id to your backend. Your backend looks the result up by request_id with its API key and scores the check-in.':
    '把 request_id 交给你的后端；后端用自己的 API 密钥按 request_id 查询结果并评估签到。',
  'Score the check-in (server-side)': '评估签到（服务端）',
  'Fetch the identify event (server-side)': '查询 identify 事件（服务端）',
  'The result shown in the browser is display-only. Keep FP_API_KEY on your server — never ship it to the browser.':
    '浏览器中显示的结果仅供展示。FP_API_KEY 必须留在服务端 —— 绝不能下发到浏览器。',

  // Hero
  'challenge → identify': '挑战 → 识别',
  'Lift a device fingerprint,': '提取设备指纹，',
  'read the verdict.': '读取判定结果。',
  'Point the collect-only client at a fingerprintd server. It collects device components, sends them with a one-time nonce and a timestamp, and the server returns a match / review / new-device call with a request_id your backend looks up.':
    '将「仅采集」客户端指向 fingerprintd 服务端：它采集设备组件，连同一次性 nonce 与时间戳一并提交，服务端返回 匹配 / 待审 / 新设备 判定以及供你的后端查询的 request_id。',

  // Empty state
  'No run yet': '尚未运行',
  Collect: '采集',
  Identify: '识别',
  'Server issues a one-time nonce.': '服务端下发一次性 nonce。',
  'Client collects device components and sends them with the nonce and a timestamp.':
    '客户端采集设备组件，连同 nonce 与时间戳一并提交。',
  'Server judges the evidence and returns a verdict plus a request_id for server-side lookup.':
    '服务端评判证据，返回判定结果以及供服务端查询的 request_id。',

  // Check-in decision-band examples
  'Check-in decision bands': '签到决策档位',
  'What the anti-farming layer decides': '反刷量层如何裁决',
  'Representative outcomes across the three decision bands — no live device farm required.':
    '覆盖三档决策的代表性结果 —— 无需真实设备农场即可查看。',
  'Returning human — allowed': '回访真人 —— 放行',
  'Device churn — challenged': '设备频繁更替 —— 验证',
  'Device farm — denied': '设备农场 —— 拒绝',
}
