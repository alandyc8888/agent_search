// Task categories (provider-listing-spec 3.2.0, controlled list v0.2) and a rule-based
// classifier for crawled items. Rules only: no LLM reads untrusted text.

export const CATEGORIES = [
  "doc.ocr", "doc.parse", "doc.summarize", "doc.translate", "doc.sign-fill",
  "file.convert", "file.compress", "file.archive", "file.validate",
  "data.scrape", "data.extract", "data.lookup", "data.business", "data.geo",
  "media.image-edit", "media.image-gen", "media.audio-transcribe", "media.tts", "media.video-edit", "media.video-gen",
  "inference.llm", "inference.embedding", "inference.rerank", "inference.vision",
  "compute.gpu", "compute.sandbox",
  "dev.code-review", "dev.test", "dev.deploy-check", "dev.search",
  "comm.email-verify", "comm.sms", "comm.notify",
  "other",
] as const;
export type Category = (typeof CATEGORIES)[number];

export const RISK_CATEGORIES = [
  "risk.escrow-arbitration", "risk.trading-signals", "risk.personal-data", "risk.human-field", "risk.credential-sale",
] as const;
