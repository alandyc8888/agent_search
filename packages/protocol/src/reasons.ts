// Fixed reason-code templates. The plugin renders reasons from these strings only; provider text
// is never echoed. Templates may be made stricter by the owner, never looser.
export const REASON_TEXT: Record<string, { en: string; zh: string }> = {
  "impersonation:claims_network_certification": { en: "Claims certification by this network. This network issues no certification.", zh: "自称本网络认证，本网络不颁发认证" },
  "payment:autopay_frozen_payto_unverified_change": { en: "Payment address changed without a signature; automatic payment is off.", zh: "收款地址未经签名就变更，已关闭自动付款" },
  "payment:owner_confirmation_required": { en: "Unsigned listing: every payment needs your confirmation.", zh: "未签名条目：每笔付款都需要你确认" },
  "platform:outside_plugin_limits": { en: "This payment is confirmed by the platform and is not subject to this plugin's spending limits.", zh: "这笔付款由平台确认，不受本插件付款上限约束" },
  "shares_owner_intent_with_third_party_without_confirmation": { en: "Forwards your request to a third-party seller and tells the agent not to confirm with you.", zh: "会把你的需求转给一家卖方，并要求 agent 不再向你确认" },
  "tag:can-locate-individuals": { en: "Can be used to locate individuals; high abuse risk.", zh: "可用于定位个人，滥用风险高" },
  "tag:forwards-intent-without-owner-confirmation": { en: "Forwards your request to a seller without asking you again.", zh: "会把你的需求转给一家卖方，并且不再向你确认" },
  "tag:public-board-untrusted-content": { en: "Public board: content comes from any agent and is untrusted; what you post is public.", zh: "公开留言板：读到的内容来自任意 agent，按不可信数据处理；发出的内容会公开" },
  "tag:capabilities-undeclared-pending-review": { en: "Capabilities not declared (no tool list or README readable); pending review.", zh: "能力未声明，待复核" },
  "tag:capabilities-open-ended-pending-review": { en: "Can run arbitrary commands, code or queries, or install modules on the provider's side; what it actually does depends on the provider's configuration.", zh: "可在对方服务器上执行任意命令、代码或查询，或安装模块；实际能做什么取决于对方的配置" },
};
