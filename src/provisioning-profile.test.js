import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { buildBinary } from "plist";
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
  return { dir, profilePath, keyPath, certPath };
}

async function signPayload(dir, payload, keyPath, certPath, name = "custom") {
  const payloadPath = path.join(dir, `${name}.payload`);
  const profilePath = path.join(dir, `${name}.mobileprovision`);
  await fs.writeFile(payloadPath, payload);
  execFileSync("openssl", [
    "cms", "-sign", "-binary", "-in", payloadPath, "-signer", certPath, "-inkey", keyPath,
    "-outform", "DER", "-out", profilePath, "-nodetach",
  ], { stdio: "ignore" });
  return profilePath;
}

function derOctetString(payload) {
  const data = Buffer.from(payload);
  let length;
  if (data.length < 0x80) {
    length = Buffer.from([data.length]);
  } else {
    const bytes = [];
    let remaining = data.length;
    while (remaining > 0) {
      bytes.unshift(remaining & 0xff);
      remaining = Math.floor(remaining / 256);
    }
    length = Buffer.from([0x80 | bytes.length, ...bytes]);
  }
  return Buffer.concat([Buffer.from([0x04]), length, data]);
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

test("decodes PEM-encoded CMS provisioning profiles", { skip: !hasOpenSsl }, async (t) => {
  const { dir, profilePath } = await makeFixture(t);
  const pemPath = path.join(dir, "fixture-pem.mobileprovision");
  execFileSync("openssl", ["cms", "-cmsout", "-inform", "DER", "-in", profilePath, "-outform", "PEM", "-out", pemPath], { stdio: "ignore" });
  const profile = await decodeProvisioningProfile(pemPath);
  assert.equal(profile.Name, "Fixture Ad Hoc");
});

test("decodes an S/MIME CMS provisioning profile", { skip: !hasOpenSsl }, async (t) => {
  const { dir, profilePath } = await makeFixture(t);
  const smimePath = path.join(dir, "fixture-smime.mobileprovision");
  execFileSync("openssl", ["cms", "-cmsout", "-inform", "DER", "-in", profilePath, "-outform", "SMIME", "-out", smimePath], { stdio: "ignore" });
  const profile = await decodeProvisioningProfile(smimePath);
  assert.equal(profile.Name, "Fixture Ad Hoc");
});

test("decodes a base64-wrapped DER CMS profile", { skip: !hasOpenSsl }, async (t) => {
  const { dir, profilePath } = await makeFixture(t);
  const base64Path = path.join(dir, "fixture-base64.mobileprovision");
  await fs.writeFile(base64Path, (await fs.readFile(profilePath)).toString("base64"));
  const profile = await decodeProvisioningProfile(base64Path);
  assert.equal(profile.Name, "Fixture Ad Hoc");
});

test("verifies Apple's nested DER-Encoded-Profile CMS when present", { skip: !hasOpenSsl }, async (t) => {
  const { dir } = await makeFixture(t);
  const innerData = path.join(dir, "inner-der.bin");
  const innerCms = path.join(dir, "inner-profile.der");
  const outerPlist = path.join(dir, "outer.plist");
  const outerProfile = path.join(dir, "outer.mobileprovision");
  // A small valid ASN.1 DER SEQUENCE payload, wrapped in its own CMS SignedData.
  await fs.writeFile(innerData, Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]));
  const keyPath = path.join(dir, "signer.key");
  const certPath = path.join(dir, "signer.crt");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "2", "-nodes", "-subj", "/CN=VANG Test Nested Signer"], { stdio: "ignore" });
  execFileSync("openssl", ["cms", "-sign", "-binary", "-in", innerData, "-signer", certPath, "-inkey", keyPath, "-outform", "DER", "-out", innerCms, "-nodetach"], { stdio: "ignore" });
  const nestedBase64 = (await fs.readFile(innerCms)).toString("base64");
  const outer = samplePlist.replace("<key>Name</key><string>Fixture Ad Hoc</string>", `<key>Name</key><string>Fixture Ad Hoc</string><key>DER-Encoded-Profile</key><string>${nestedBase64}</string>`);
  await fs.writeFile(outerPlist, outer);
  execFileSync("openssl", ["cms", "-sign", "-binary", "-in", outerPlist, "-signer", certPath, "-inkey", keyPath, "-outform", "DER", "-out", outerProfile, "-nodetach"], { stdio: "ignore" });
  const profile = await decodeProvisioningProfile(outerProfile);
  assert.equal(profile.Name, "Fixture Ad Hoc");
  assert.equal(typeof profile["DER-Encoded-Profile"], "string");
});

test("rejects a plain plist file because it has no Apple CMS wrapper", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "profile-plain-test-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const profilePath = path.join(dir, "plain.mobileprovision");
  await fs.writeFile(profilePath, samplePlist);
  await assert.rejects(decodeProvisioningProfile(profilePath), (error) => {
    assert.equal(error.code, "UNSIGNED_PROVISIONING_PROFILE");
    assert.match(error.message, /plist thô/);
    return true;
  });
});


test("decodes a CMS payload wrapped in a complete DER OCTET STRING", { skip: !hasOpenSsl }, async (t) => {
  const { dir, keyPath, certPath } = await makeFixture(t);
  const profilePath = await signPayload(dir, derOctetString(Buffer.from(samplePlist)), keyPath, certPath, "octet-wrapped");
  const profile = await decodeProvisioningProfile(profilePath);
  assert.equal(profile.Name, "Fixture Ad Hoc");
});

test("decodes a Base64-encoded XML plist CMS payload", { skip: !hasOpenSsl }, async (t) => {
  const { dir, keyPath, certPath } = await makeFixture(t);
  const base64Payload = Buffer.from(samplePlist).toString("base64");
  const profilePath = await signPayload(dir, Buffer.from(base64Payload), keyPath, certPath, "base64-plist");
  const profile = await decodeProvisioningProfile(profilePath);
  assert.equal(profile.Name, "Fixture Ad Hoc");
});

test("decodes a CMS-signed binary plist payload", { skip: !hasOpenSsl }, async (t) => {
  const { dir, keyPath, certPath } = await makeFixture(t);
  const object = {
    Name: "Binary Fixture",
    UUID: "00000000-0000-0000-0000-000000000002",
    ExpirationDate: new Date("2030-01-01T00:00:00Z"),
    Entitlements: { "get-task-allow": false, "application-identifier": "ABCDE12345.com.example.binary" },
    DeveloperCertificates: [Buffer.from([0x01, 0x02, 0x03])],
    ProvisionedDevices: ["0123456789ABCDEF0123456789ABCDEF01234567"],
  };
  const profilePath = await signPayload(dir, Buffer.from(buildBinary(object)), keyPath, certPath, "binary-plist");
  const profile = await decodeProvisioningProfile(profilePath);
  assert.equal(profile.Name, "Binary Fixture");
  assert.equal(profile.Entitlements["application-identifier"], "ABCDE12345.com.example.binary");
});

test("verifies an inner CMS payload before parsing its plist", { skip: !hasOpenSsl }, async (t) => {
  const { dir, keyPath, certPath } = await makeFixture(t);
  const innerPath = await signPayload(dir, Buffer.from(samplePlist), keyPath, certPath, "inner");
  const innerCms = await fs.readFile(innerPath);
  const outerPath = await signPayload(dir, innerCms, keyPath, certPath, "outer-inner-cms");
  const profile = await decodeProvisioningProfile(outerPath);
  assert.equal(profile.Name, "Fixture Ad Hoc");
});
