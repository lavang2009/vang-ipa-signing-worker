import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { getPkcs12CertificateFingerprints, preparePkcs12ForSigning } from "./pkcs12.js";

const hasOpenSsl = (() => {
  try { execFileSync("openssl", ["version"], { stdio: "ignore" }); return true; }
  catch { return false; }
})();

test("extracts public certificate SHA-256 fingerprint from a P12 without exposing its key", { skip: !hasOpenSsl }, async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vang-p12-test-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const keyPath = path.join(dir, "key.pem");
  const certPath = path.join(dir, "cert.pem");
  const p12Path = path.join(dir, "cert.p12");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath,
    "-days", "2", "-nodes", "-subj", "/CN=VANG P12 Test",
  ], { stdio: "ignore" });
  execFileSync("openssl", [
    "pkcs12", "-export", "-in", certPath, "-inkey", keyPath, "-out", p12Path,
    "-passout", "pass:test-password",
  ], { stdio: "ignore" });

  const fingerprints = await getPkcs12CertificateFingerprints(p12Path, "test-password");
  assert.equal(fingerprints.length, 1);
  assert.match(fingerprints[0], /^[a-f0-9]{64}$/);

  const normalizedPath = await preparePkcs12ForSigning(p12Path, dir, "test-password");
  assert.equal(normalizedPath, p12Path);
});

test("rejects an incorrect P12 password without logging secrets", { skip: !hasOpenSsl }, async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vang-p12-bad-pass-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const keyPath = path.join(dir, "key.pem");
  const certPath = path.join(dir, "cert.pem");
  const p12Path = path.join(dir, "cert.p12");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath,
    "-days", "2", "-nodes", "-subj", "/CN=VANG P12 Bad Pass Test",
  ], { stdio: "ignore" });
  execFileSync("openssl", [
    "pkcs12", "-export", "-in", certPath, "-inkey", keyPath, "-out", p12Path,
    "-passout", "pass:correct-password",
  ], { stdio: "ignore" });

  await assert.rejects(getPkcs12CertificateFingerprints(p12Path, "wrong-password"), (error) => {
    assert.equal(error.code, "INVALID_PKCS12");
    assert.equal(error.message.includes("wrong-password"), false);
    return true;
  });
});
