import test from "node:test";
import assert from "node:assert/strict";
import { build, buildBinary } from "plist";
import { parseIpaInfoPlist } from "./ipa-info-plist.js";

const fixture = {
  CFBundleIdentifier: "com.example.vangstore",
  CFBundleVersion: "12",
  CFBundleDisplayName: "VANG STORE",
};

test("parses XML Info.plist as UTF-8 text", () => {
  const xml = Buffer.from(build(fixture), "utf8");
  const parsed = parseIpaInfoPlist(xml);
  assert.equal(parsed.format, "XML_PLIST");
  assert.equal(parsed.value.CFBundleIdentifier, fixture.CFBundleIdentifier);
});

test("parses XML Info.plist with UTF-8 BOM and leading whitespace", () => {
  const xml = Buffer.from(`\uFEFF  ${build(fixture)}`, "utf8");
  const parsed = parseIpaInfoPlist(xml);
  assert.equal(parsed.format, "XML_PLIST");
  assert.equal(parsed.value.CFBundleVersion, fixture.CFBundleVersion);
});

test("parses Binary Info.plist only when bplist00 magic is present", () => {
  const binary = Buffer.from(buildBinary(fixture));
  assert.equal(binary.subarray(0, 8).toString("ascii"), "bplist00");
  const parsed = parseIpaInfoPlist(binary);
  assert.equal(parsed.format, "BINARY_PLIST");
  assert.equal(parsed.value.CFBundleIdentifier, fixture.CFBundleIdentifier);
});

test("reports unknown Info.plist headers with a specific error code", () => {
  assert.throws(
    () => parseIpaInfoPlist(Buffer.from("not a plist")),
    (error) => error.code === "INVALID_IPA_INFO_PLIST" && error.payloadFormat === "UNKNOWN",
  );
});

test("rejects a valid plist whose root is not a dictionary", () => {
  assert.throws(
    () => parseIpaInfoPlist(Buffer.from(build("not-a-dictionary"), "utf8")),
    (error) => error.code === "INVALID_IPA_INFO_PLIST",
  );
});
