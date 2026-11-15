import test from "node:test";
import assert from "node:assert/strict";
import { validateCertificateArchiveEntries } from "./archive-validation.js";

const validZip = [
  "Certificates/",
  "Certificates/distribution.p12",
  "ProvisioningProfiles/",
  "ProvisioningProfiles/app.mobileprovision",
];

test("accepts the original two-folder archive", () => {
  assert.deepEqual(validateCertificateArchiveEntries(validZip), {
    p12Entry: "Certificates/distribution.p12",
    profileEntry: "ProvisioningProfiles/app.mobileprovision",
  });
});

test("accepts a wrapper folder and nested certificate folders", () => {
  assert.deepEqual(validateCertificateArchiveEntries([
    "ExportedCertificates/",
    "ExportedCertificates/AppleDistribution/",
    "ExportedCertificates/AppleDistribution/distribution.p12",
    "ExportedCertificates/Profiles/",
    "ExportedCertificates/Profiles/app.mobileprovision",
  ]), {
    p12Entry: "ExportedCertificates/AppleDistribution/distribution.p12",
    profileEntry: "ExportedCertificates/Profiles/app.mobileprovision",
  });
});

test("accepts root README and other harmless files", () => {
  assert.deepEqual(validateCertificateArchiveEntries([
    "README.txt",
    "certificate-info.pdf",
    ...validZip,
    "Notes/installation.txt",
  ]), {
    p12Entry: "Certificates/distribution.p12",
    profileEntry: "ProvisioningProfiles/app.mobileprovision",
  });
});

test("accepts ZIPs prefixed with ./", () => {
  assert.deepEqual(validateCertificateArchiveEntries([
    "./",
    "./Certificates/",
    "./Certificates/distribution.p12",
    "./Profiles/",
    "./Profiles/app.mobileprovision",
  ]), {
    p12Entry: "./Certificates/distribution.p12",
    profileEntry: "./Profiles/app.mobileprovision",
  });
});

test("ignores macOS and Windows archive metadata", () => {
  assert.deepEqual(validateCertificateArchiveEntries([
    ...validZip,
    "__MACOSX/",
    "__MACOSX/._distribution.p12",
    "Certificates/.DS_Store",
    "Thumbs.db",
    "desktop.ini",
  ]), {
    p12Entry: "Certificates/distribution.p12",
    profileEntry: "ProvisioningProfiles/app.mobileprovision",
  });
});

test("rejects missing credential files with specific messages", () => {
  assert.throws(() => validateCertificateArchiveEntries(["Certificates/readme.txt"]), /Không tìm thấy chứng chỉ/);
  assert.throws(() => validateCertificateArchiveEntries(["Certificates/cert.p12"]), /Không tìm thấy provisioning profile/);
});

test("rejects duplicate P12 and provisioning profiles", () => {
  assert.throws(() => validateCertificateArchiveEntries([
    "A/one.p12", "B/two.pfx", "C/app.mobileprovision",
  ]), /nhiều file \.p12/);
  assert.throws(() => validateCertificateArchiveEntries([
    "A/one.p12", "B/one.mobileprovision", "C/two.mobileprovision",
  ]), /nhiều file \.mobileprovision/);
});

test("rejects unsafe or ambiguous paths", () => {
  assert.throws(() => validateCertificateArchiveEntries([
    "Certificates/../cert.p12", "Profiles/profile.mobileprovision",
  ]), /không an toàn/);
  assert.throws(() => validateCertificateArchiveEntries([
    "C:/Certificates/cert.p12", "Profiles/profile.mobileprovision",
  ]), /không hợp lệ/);
  assert.throws(() => validateCertificateArchiveEntries([
    "Certificates\\cert.p12", "Profiles/profile.mobileprovision",
  ]), /không hợp lệ/);
});
