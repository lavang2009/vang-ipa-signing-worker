import test from "node:test";
import assert from "node:assert/strict";
import { validateCertificateArchiveEntries } from "./archive-validation.js";

const validZip = [
  "Certificates/",
  "Certificates/distribution.p12",
  "ProvisioningProfiles/",
  "ProvisioningProfiles/app.mobileprovision",
];

test("accepts exactly two certificate folders and the required two files", () => {
  assert.deepEqual(validateCertificateArchiveEntries(validZip), {
    p12Entry: "Certificates/distribution.p12",
    profileEntry: "ProvisioningProfiles/app.mobileprovision",
  });
});

test("accepts arbitrary folder names when the two required files are separated", () => {
  assert.doesNotThrow(() => validateCertificateArchiveEntries([
    "Folder A/cert.pfx", "Folder B/profile.mobileprovision",
  ]));
});

test("rejects a missing folder or extra folder", () => {
  assert.throws(() => validateCertificateArchiveEntries(["Certificates/cert.p12"]), /đúng hai thư mục/);
  assert.throws(() => validateCertificateArchiveEntries([...validZip, "Extras/"]), /đúng hai thư mục/);
});

test("rejects extra files and duplicate credential files", () => {
  assert.throws(() => validateCertificateArchiveEntries([...validZip, "Certificates/readme.txt"]), /chỉ được chứa hai tệp/);
  assert.throws(() => validateCertificateArchiveEntries([...validZip, "Certificates/second.p12"]), /chỉ được chứa hai tệp/);
});

test("rejects nested folders and traversal paths", () => {
  assert.throws(() => validateCertificateArchiveEntries([
    "Certificates/", "Certificates/sub/", "Certificates/cert.p12", "Profiles/profile.mobileprovision",
  ]), /không tạo thêm thư mục con/);
  assert.throws(() => validateCertificateArchiveEntries([
    "Certificates/../cert.p12", "Profiles/profile.mobileprovision",
  ]), /không an toàn/);
});

test("ignores common macOS archive metadata", () => {
  assert.doesNotThrow(() => validateCertificateArchiveEntries([
    ...validZip, "__MACOSX/", "__MACOSX/._distribution.p12", "Certificates/.DS_Store",
  ]));
});
