import test from "node:test";
import assert from "node:assert/strict";
import { applyCors, buildAllowedOrigins, parseAllowedOrigins } from "./cors.js";

function responseStub(initialHeaders = {}) {
  const headers = new Map(Object.entries(initialHeaders));
  return {
    headers,
    getHeader(name) { return headers.get(name); },
    setHeader(name, value) { headers.set(name, value); },
  };
}

test("parses a strict comma/semicolon/newline-separated origin allow-list", () => {
  const allowed = parseAllowedOrigins("https://luavang.store, https://www.luavang.store/;\nhttps://preview.example.com");
  assert.deepEqual([...allowed].sort(), [
    "https://luavang.store",
    "https://preview.example.com",
    "https://www.luavang.store",
  ]);
});

test("does not turn a path, credential, or unsupported scheme into an allowed origin", () => {
  const allowed = parseAllowedOrigins("https://luavang.store/sign-ipa, javascript://example.com, https://user:pass@example.com, https://*.example.com");
  assert.deepEqual([...allowed], []);
});

test("allows an exact origin and returns all headers needed for Bearer-authenticated preflight", () => {
  const allowed = parseAllowedOrigins("https://luavang.store");
  const res = responseStub({ Vary: "Accept-Encoding" });
  const accepted = applyCors({ headers: { origin: "https://luavang.store" } }, res, allowed);

  assert.equal(accepted, true);
  assert.equal(res.getHeader("Access-Control-Allow-Origin"), "https://luavang.store");
  assert.equal(res.getHeader("Access-Control-Allow-Headers"), "Authorization, Content-Type");
  assert.equal(res.getHeader("Access-Control-Allow-Methods"), "POST, OPTIONS, GET");
  assert.equal(res.getHeader("Vary"), "Accept-Encoding, Origin");
});

test("rejects a different origin and keeps Vary: Origin on the denial", () => {
  const allowed = parseAllowedOrigins("https://luavang.store");
  const res = responseStub();
  const accepted = applyCors({ headers: { origin: "https://attacker.example" } }, res, allowed);

  assert.equal(accepted, false);
  assert.equal(res.getHeader("Access-Control-Allow-Origin"), undefined);
  assert.equal(res.getHeader("Vary"), "Origin");
});

test("allows server-to-server calls without Origin", () => {
  const res = responseStub();
  assert.equal(applyCors({ headers: {} }, res, new Set()), true);
  assert.equal(res.getHeader("Access-Control-Allow-Origin"), undefined);
});


test("always allows both exact VANG STORE production domains", () => {
  const allowed = buildAllowedOrigins("");
  assert.equal(allowed.has("https://luavang.store"), true);
  assert.equal(allowed.has("https://www.luavang.store"), true);
  assert.equal(allowed.has("https://evil.example"), false);
});

test("adds configured exact origins without allowing wildcard origins", () => {
  const allowed = buildAllowedOrigins("https://preview.luavang.store,https://*.luavang.store");
  assert.equal(allowed.has("https://preview.luavang.store"), true);
  assert.equal(allowed.has("https://*.luavang.store"), false);
});


test("CORS middleware returns headers for the www production origin", () => {
  const allowed = buildAllowedOrigins("");
  const res = responseStub();
  const accepted = applyCors({ headers: { origin: "https://www.luavang.store" } }, res, allowed);
  assert.equal(accepted, true);
  assert.equal(res.getHeader("Access-Control-Allow-Origin"), "https://www.luavang.store");
});
