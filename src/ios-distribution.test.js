import test from "node:test";
import assert from "node:assert/strict";
import {
  assertProvisioningProfileUsable,
  buildItmsServicesUrl,
  buildOtaManifestXml,
  classifyProvisioningProfile,
  isBundleIdentifierAllowed,
  isDeviceRegistered,
  normalizeDeviceUdid,
} from "./ios-distribution.js";

const future = new Date(Date.now() + 86_400_000);
const udidA = "0123456789ABCDEF0123456789ABCDEF01234567";
const udidB = "89ABCDEF0123456789ABCDEF0123456789ABCDEF";

function adhocProfile(overrides = {}) {
  return {
    ProvisionsAllDevices: false,
    ProvisionedDevices: [udidA, udidB],
    ExpirationDate: future,
    Entitlements: {
      "get-task-allow": false,
      "application-identifier": "ABCDE12345.com.example.app",
    },
    ...overrides,
  };
}

test("classifies a registered-device profile as Ad Hoc", () => {
  const info = classifyProvisioningProfile(adhocProfile());
  assert.equal(info.type, "ad-hoc");
  assert.equal(info.registeredDeviceCount, 2);
  assert.equal(info.expiresAt, future.toISOString());
});

test("classifies enterprise and development profiles", () => {
  assert.equal(classifyProvisioningProfile({ ProvisionsAllDevices: true, ExpirationDate: future }).type, "enterprise");
  assert.equal(classifyProvisioningProfile({ ProvisionedDevices: [udidA], Entitlements: { "get-task-allow": true }, ExpirationDate: future }).type, "development");
});

test("rejects expired or unidentified provisioning profiles", () => {
  assert.throws(() => assertProvisioningProfileUsable({ type: "unknown", expiresAt: future.toISOString() }), /Không xác định/);
  assert.throws(() => assertProvisioningProfileUsable({ type: "ad-hoc", registeredDeviceCount: 1, expiresAt: new Date(0).toISOString() }), /đã hết hạn/);
  assert.throws(() => assertProvisioningProfileUsable({ type: "ad-hoc", registeredDeviceCount: 0, expiresAt: future.toISOString() }), /không có thiết bị/);
});

test("matches exact and wildcard App IDs", () => {
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.app", "com.example.app"), true);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.*", "com.example.demo"), true);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.*", "com.other.demo"), false);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.*", "com.example.app"), true);
});

test("normalizes and validates a supplied device UDID", () => {
  assert.equal(normalizeDeviceUdid(udidA.toLowerCase()), udidA);
  assert.equal(normalizeDeviceUdid(""), "");
  assert.throws(() => normalizeDeviceUdid("1234"), /40 ký tự/);
  const info = classifyProvisioningProfile(adhocProfile());
  assert.equal(isDeviceRegistered(info, udidA), true);
  assert.equal(isDeviceRegistered(info, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), false);
});

test("builds a valid OTA manifest with escaped values", () => {
  const xml = buildOtaManifestXml({
    ipaUrl: "https://example.com/app.ipa?token=a%26b",
    bundleIdentifier: "com.example.app",
    bundleVersion: "1.2.3",
    title: "A & B App",
  });
  assert.match(xml, /<key>kind<\/key><string>software-package<\/string>/);
  assert.match(xml, /A &amp; B App/);
  assert.match(xml, /com.example.app/);
});

test("builds an itms-services URL only from HTTPS manifest URLs", () => {
  const link = buildItmsServicesUrl("https://example.com/manifest.plist?sig=abc");
  assert.match(link, /^itms-services:\/\//);
  assert.match(link, /download-manifest/);
  assert.throws(() => buildItmsServicesUrl("http://example.com/manifest.plist"), /HTTPS/);
});
