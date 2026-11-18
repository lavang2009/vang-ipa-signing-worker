import test from "node:test";
import assert from "node:assert/strict";
import { isIpaSigningMaintenanceBlocked, normalizeIpaSigningMaintenance } from "./maintenance.js";

test("missing maintenance document defaults to disabled with safe copy", () => {
  const state = normalizeIpaSigningMaintenance();
  assert.equal(state.enabled, false);
  assert.match(state.title, /bảo trì/i);
  assert.ok(state.message.length > 0);
});

test("only a boolean true enables maintenance", () => {
  assert.equal(normalizeIpaSigningMaintenance({ enabled: "true" }).enabled, false);
  assert.equal(normalizeIpaSigningMaintenance({ enabled: 1 }).enabled, false);
  assert.equal(normalizeIpaSigningMaintenance({ enabled: true }).enabled, true);
});

test("maintenance notice fields are trimmed and length-limited", () => {
  const state = normalizeIpaSigningMaintenance({
    enabled: true,
    title: ` ${"T".repeat(200)} `,
    message: "  Xin quay lại sau.  ",
    estimatedReturn: ` ${"R".repeat(200)} `,
  });
  assert.equal(state.title.length, 120);
  assert.equal(state.message, "Xin quay lại sau.");
  assert.equal(state.estimatedReturn.length, 120);
});

test("IPA maintenance blocks regular users but lets verified admins through", () => {
  const enabled = normalizeIpaSigningMaintenance({ enabled: true });
  const disabled = normalizeIpaSigningMaintenance({ enabled: false });
  assert.equal(isIpaSigningMaintenanceBlocked(enabled, false), true);
  assert.equal(isIpaSigningMaintenanceBlocked(enabled, true), false);
  assert.equal(isIpaSigningMaintenanceBlocked(disabled, false), false);
});
