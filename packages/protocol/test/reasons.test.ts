import { describe, expect, it } from "vitest";
import { REASON_TEXT } from "../src/reasons.ts";

describe("public reason templates", () => {
  it.each([
    "content:hidden_characters", "content:instruction_like_text", "identity:unverified_ownership",
    "identity:unverified_certification_claim", "identity:hosted_namespace", "payment:unverified_recipient_or_instruction",
    "capability:insufficient_disclosure", "capability:open_ended", "capability:personal_data_related",
    "capability:definition_changed", "metadata:invalid_description", "service:upstream_or_terms_risk",
    "service:untrusted_third_party_content", "action:confirm_third_party_sharing", "platform:checkout_handed_to_owner",
    "platform:outside_plugin_limits", "payment:owner_confirmation_required", "credit:not_counted",
  ])("renders a fixed bilingual template for %s", (code) => {
    expect(REASON_TEXT[code].en.length).toBeGreaterThan(10);
    expect(REASON_TEXT[code].zh.length).toBeGreaterThan(5);
  });
  it("retains fixed legacy aliases without accepting arbitrary external text", () => {
    expect(REASON_TEXT["impersonation:claims_network_certification"]).toBeDefined();
    expect(REASON_TEXT["payment:autopay_frozen_payto_unverified_change"]).toBeDefined();
    expect(Object.hasOwn(REASON_TEXT, "unknown:provider_supplied_text")).toBe(false);
  });
});
