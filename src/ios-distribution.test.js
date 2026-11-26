import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  assertProvisioningProfileUsable,
  assertTargetDeviceAllowed,
  assertBundleIdentifierAllowed,
  assertOriginalBundleIdentifier,
  assertSigningCertificateInProfile,
  getApplicationIdentifierParts,
  buildItmsServicesUrl,
  buildOtaManifestXml,
  classifyProvisioningProfile,
  isBundleIdentifierAllowed,
} from "./ios-distribution.js";

const future = new Date(Date.now() + 86_400_000);
const udidA = "0123456789ABCDEF0123456789ABCDEF01234567";
const udidB = "89ABCDEF0123456789ABCDEF0123456789ABCDEF";
const modernUdid = "00008030-001C2D3E4F5A6B7C";

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

test("classifies a registered-device profile as Ad Hoc and exposes safe App ID diagnostics", () => {
  const info = classifyProvisioningProfile(adhocProfile({
    Name: "Test profile",
    UUID: "PROFILE-UUID-1",
    TeamIdentifier: ["TEAM123456"],
  }));
  assert.equal(info.type, "ad-hoc");
  assert.equal(info.registeredDeviceCount, 2);
  assert.equal(info.expiresAt, future.toISOString());
  assert.equal(info.appIdPrefix, "ABCDE12345");
  assert.equal(info.profileBundlePattern, "com.example.app");
  assert.equal(info.profileName, "Test profile");
  assert.equal(info.profileUuid, "PROFILE-UUID-1");
  assert.deepEqual(info.teamIdentifiers, ["TEAM123456"]);
});

test("classifies enterprise and development profiles", () => {
  assert.equal(classifyProvisioningProfile({ ProvisionsAllDevices: true, ExpirationDate: future }).type, "enterprise");
  assert.equal(classifyProvisioningProfile({ ProvisionedDevices: [udidA], Entitlements: { "get-task-allow": true }, ExpirationDate: future }).type, "development");
});

test("rejects expired or unidentified provisioning profiles", () => {
  assert.throws(() => assertProvisioningProfileUsable({ type: "other", applicationIdentifier: "ABCDE12345.com.example.app", expiresAt: new Date(0).toISOString() }), /đã hết hạn/);
  assert.throws(() => assertProvisioningProfileUsable({ type: "ad-hoc", registeredDeviceCount: 1, expiresAt: future.toISOString() }), /application-identifier/);
});

test("matches exact and wildcard App IDs", () => {
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.app", "com.example.app"), true);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.*", "com.example.demo"), true);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.*", "com.example.demo.extension"), true);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.*", "com.other.demo"), false);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.*", "com.example.app"), true);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.app", "com.example.other"), false);
});

test("uses App ID Prefix from application-identifier, not an assumed Team ID", () => {
  // Historical App ID prefixes may differ from the current Team ID.
  assert.equal(isBundleIdentifierAllowed("OLDPREFIX99.com.example.legacy", "com.example.legacy"), true);
});

test("validates wildcard shape and rejects malformed Bundle IDs", () => {
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.*", "com.example"), false);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.*", "com.example."), false);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.*.app", "com.example.app"), false);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.*.child", "com.example.demo"), false);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.app", "com..example.app"), false);
  assert.equal(isBundleIdentifierAllowed("ABCDE12345.com.example.app", "com.example.app/other"), false);
});

test("returns actionable mismatch diagnostics without accepting an incompatible App ID", () => {
  assert.equal(assertBundleIdentifierAllowed("ABCDE12345.com.example.app", "com.example.app"), true);
  assert.throws(
    () => assertBundleIdentifierAllowed("ABCDE12345.com.example.app", "com.other.app"),
    (error) => error.code === "BUNDLE_ID_PROFILE_MISMATCH" &&
      error.details.bundleIdentifier === "com.other.app" &&
      error.details.applicationIdentifier === "ABCDE12345.com.example.app",
  );
});



test("rejects the reported IPA/profile pair while preserving the original Bundle ID", () => {
  const sourceBundleId = "p3.xyz.yyyue.esign";
  const profileApplicationIdentifier = "2FRGLDX9FA.com.Azor255588.Azor";
  assert.equal(assertOriginalBundleIdentifier(sourceBundleId), sourceBundleId);
  assert.throws(
    () => assertBundleIdentifierAllowed(profileApplicationIdentifier, sourceBundleId, {
      profileName: "Azor profile",
      profileUuid: "reported-profile",
      teamIdentifiers: ["2FRGLDX9FA"],
    }),
    (error) => error.code === "BUNDLE_ID_PROFILE_MISMATCH" &&
      error.details.sourceBundleIdentifier === sourceBundleId &&
      error.details.applicationIdentifier === profileApplicationIdentifier &&
      error.details.profileBundlePattern === "com.Azor255588.Azor" &&
      error.details.nextAction === "DOWNLOAD_MATCHING_PROVISIONING_PROFILE_FROM_APPLE_DEVELOPER",
  );
});

test("extracts App ID prefix and wildcard pattern without confusing it with Team ID", () => {
  assert.deepEqual(getApplicationIdentifierParts("2FRGLDX9FA.com.Azor255588.Azor"), {
    appIdPrefix: "2FRGLDX9FA",
    profileBundlePattern: "com.Azor255588.Azor",
  });
  assert.deepEqual(getApplicationIdentifierParts("OLDPREFIX99.com.example.*"), {
    appIdPrefix: "OLDPREFIX99",
    profileBundlePattern: "com.example.*",
  });
  assert.equal(getApplicationIdentifierParts("missing-separator"), null);
});

test("preserves the IPA original Bundle ID and rejects requested rewrites", () => {
  assert.equal(assertOriginalBundleIdentifier("p3.xyz.yyyue.esign", ""), "p3.xyz.yyyue.esign");
  assert.equal(assertOriginalBundleIdentifier("p3.xyz.yyyue.esign", "p3.xyz.yyyue.esign"), "p3.xyz.yyyue.esign");
  assert.throws(
    () => assertOriginalBundleIdentifier("p3.xyz.yyyue.esign", "com.Azor255588.Azor"),
    (error) => error.code === "BUNDLE_ID_OVERRIDE_DISABLED" &&
      error.details.sourceBundleIdentifier === "p3.xyz.yyyue.esign" &&
      error.details.requestedBundleIdentifier === "com.Azor255588.Azor",
  );
});

test("mismatch diagnostics explain the exact profile pattern and preserve-source policy", () => {
  assert.throws(
    () => assertBundleIdentifierAllowed(
      "2FRGLDX9FA.com.Azor255588.Azor",
      "p3.xyz.yyyue.esign",
      { profileName: "Azor Profile", profileUuid: "PROFILE-UUID", teamIdentifiers: ["2FRGLDX9FA"] },
    ),
    (error) => error.code === "BUNDLE_ID_PROFILE_MISMATCH" &&
      error.details.appIdPrefix === "2FRGLDX9FA" &&
      error.details.profileBundlePattern === "com.Azor255588.Azor" &&
      error.details.sourceBundleIdentifier === "p3.xyz.yyyue.esign" &&
      error.details.profileName === "Azor Profile" &&
      error.details.policy === "PRESERVE_SOURCE_BUNDLE_ID" &&
      error.details.nextAction === "DOWNLOAD_MATCHING_PROVISIONING_PROFILE_FROM_APPLE_DEVELOPER",
  );
});

test("requires the P12 certificate fingerprint to be present in DeveloperCertificates", () => {
  const certificateBytes = Buffer.from([0x30, 0x03, 0x02, 0x01, 0x01]);
  const fingerprint = (crypto.createHash("sha256").update(certificateBytes).digest("hex"));
  assert.equal(assertSigningCertificateInProfile({ DeveloperCertificates: [certificateBytes] }, [fingerprint]), true);
  assert.throws(
    () => assertSigningCertificateInProfile({ DeveloperCertificates: [certificateBytes] }, ["00".repeat(32)]),
    (error) => error.code === "SIGNING_CERTIFICATE_NOT_IN_PROFILE" && error.details.matchingCertificate === false,
  );
});

test("keeps Ad Hoc and Development device restrictions when no target UDID is supplied", () => {
  const adHoc = classifyProvisioningProfile(adhocProfile());
  const development = classifyProvisioningProfile(adhocProfile({ Entitlements: {
    "get-task-allow": true,
    "application-identifier": "ABCDE12345.com.example.app",
  } }));
  assert.equal(adHoc.type, "ad-hoc");
  assert.equal(adHoc.registeredDeviceCount, 2);
  assert.equal(development.type, "development");
  assert.equal(development.registeredDeviceCount, 2);
  // Without a target UDID, the signed profile remains authoritative and iOS
  // enforces its registered-device list at installation time.
});

test("classifies every standard iOS profile type for signing", () => {
  assert.equal(classifyProvisioningProfile(adhocProfile()).type, "ad-hoc");
  assert.equal(classifyProvisioningProfile({ ProvisionsAllDevices: true, ExpirationDate: future, Entitlements: { "application-identifier": "ABCDE12345.com.example.app" } }).type, "enterprise");
  assert.equal(classifyProvisioningProfile({ ProvisionedDevices: [udidA], Entitlements: { "get-task-allow": true }, ExpirationDate: future }).type, "development");
  assert.equal(classifyProvisioningProfile({ Entitlements: { "get-task-allow": false }, ExpirationDate: future }).type, "app-store");
  assert.equal(classifyProvisioningProfile({ Entitlements: {}, ExpirationDate: future }).type, "other");
});

test("reads the macOS/Catalyst application-identifier entitlement fallback", () => {
  const info = classifyProvisioningProfile({
    ExpirationDate: future,
    Entitlements: { "com.apple.application-identifier": "LEGACYPREFIX.com.example.catalyst" },
  });
  assert.equal(info.applicationIdentifier, "LEGACYPREFIX.com.example.catalyst");
  assert.equal(isBundleIdentifierAllowed(info.applicationIdentifier, "com.example.catalyst"), true);
});

test("allows valid non-Ad Hoc profiles to pass profile eligibility checks", () => {
  for (const type of ["enterprise", "development", "app-store", "other"]) {
    assert.equal(assertProvisioningProfileUsable({
      type,
      expiresAt: future.toISOString(),
      applicationIdentifier: "ABCDE12345.com.example.app",
    }).type, type);
  }
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


test("accepts a target UDID that is listed in Ad Hoc or Development profile", () => {
  const info = classifyProvisioningProfile(adhocProfile());
  assert.deepEqual(assertTargetDeviceAllowed(info, udidA.toLowerCase()), { provided: true, registered: true });
});

test("accepts a listed 25-character UDID in Ad Hoc and Development profiles", () => {
  for (const type of ["ad-hoc", "development"]) {
    const info = classifyProvisioningProfile(adhocProfile({
      ProvisionedDevices: [modernUdid],
      Entitlements: {
        "get-task-allow": type === "development",
        "application-identifier": "ABCDE12345.com.example.app",
      },
    }));
    assert.equal(info.type, type);
    assert.deepEqual(assertTargetDeviceAllowed(info, modernUdid.toLowerCase()), { provided: true, registered: true });
  }
});

test("rejects a target UDID that is not registered in Ad Hoc profile", () => {
  const info = classifyProvisioningProfile(adhocProfile());
  assert.throws(() => assertTargetDeviceAllowed(info, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), (error) => error.code === "TARGET_DEVICE_NOT_REGISTERED");
});

test("keeps target UDID optional and validates its format", () => {
  const info = classifyProvisioningProfile(adhocProfile());
  assert.deepEqual(assertTargetDeviceAllowed(info, ""), { provided: false, registered: null });
  assert.throws(() => assertTargetDeviceAllowed(info, "not-a-udid"), (error) => error.code === "INVALID_TARGET_UDID");
});

test("does not require UDID for unrestricted enterprise profile", () => {
  const info = classifyProvisioningProfile({ ProvisionsAllDevices: true, ExpirationDate: future, Entitlements: { "application-identifier": "ABCDE12345.com.example.app" } });
  assert.deepEqual(assertTargetDeviceAllowed(info, udidA), { provided: true, registered: null });
});
