import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { decodeProvisioningProfile } from "./provisioning-profile.js";

const hasOpenSsl = (() => {
  try { execFileSync("openssl", ["version"], { stdio: "ignore" }); return true; }
  catch { return false; }
})();

const samplePlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Name</key><string>Fixture Ad Hoc</string>
<key>UUID</key><string>00000000-0000-0000-0000-000000000001</string>
<key>ExpirationDate</key><date>2030-01-01T00:00:00Z</date>
<key>Entitlements</key><dict><key>get-task-allow</key><false/><key>application-identifier</key><string>ABCDE12345.com.example.app</string></dict>
<key>DeveloperCertificates</key><array><data>AA==</data></array>
<key>ProvisionedDevices</key><array><string>0123456789ABCDEF0123456789ABCDEF01234567</string></array>
</dict></plist>`;

async function makeFixture(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "profile-cms-test-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const plistPath = path.join(dir, "payload.plist");
  const keyPath = path.join(dir, "signer.key");
  const certPath = path.join(dir, "signer.crt");
  const profilePath = path.join(dir, "fixture.mobileprovision");
  await fs.writeFile(plistPath, samplePlist);
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath,
    "-days", "2", "-nodes", "-subj", "/CN=VANG Test Profile Signer",
  ], { stdio: "ignore" });
  execFileSync("openssl", [
    "cms", "-sign", "-binary", "-in", plistPath, "-signer", certPath, "-inkey", keyPath,
    "-outform", "DER", "-out", profilePath, "-nodetach",
  ], { stdio: "ignore" });
  return { dir, profilePath };
}

test("decodes a valid CMS-signed provisioning profile using OpenSSL", { skip: !hasOpenSsl }, async (t) => {
  const { profilePath } = await makeFixture(t);
  const profile = await decodeProvisioningProfile(profilePath);
  assert.equal(profile.Name, "Fixture Ad Hoc");
  assert.equal(profile.Entitlements["application-identifier"], "ABCDE12345.com.example.app");
  assert.equal(profile.ProvisionedDevices.length, 1);
  assert.ok(profile.ExpirationDate instanceof Date);
  assert.equal(profile.DeveloperCertificates.length, 1);
});

test("rejects a tampered CMS profile with a precise error code", { skip: !hasOpenSsl }, async (t) => {
  const { dir, profilePath } = await makeFixture(t);
  const tamperedPath = path.join(dir, "tampered.mobileprovision");
  const bytes = await fs.readFile(profilePath);
  bytes[bytes.length - 8] ^= 0x01;
  await fs.writeFile(tamperedPath, bytes);
  await assert.rejects(decodeProvisioningProfile(tamperedPath), (error) => {
    assert.equal(error.code, "INVALID_PROVISIONING_PROFILE_CMS");
    return true;
  });
});

test("rejects a plain plist file because it has no Apple CMS wrapper", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "profile-plain-test-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const profilePath = path.join(dir, "plain.mobileprovision");
  await fs.writeFile(profilePath, samplePlist);
  await assert.rejects(decodeProvisioningProfile(profilePath), (error) => {
    assert.equal(error.code, "INVALID_PROVISIONING_PROFILE_CMS");
    assert.match(error.message, /plist thô/);
    return true;
  });
});
