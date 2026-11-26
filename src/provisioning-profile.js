import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { parse as parsePlist } from "plist";

const execFileAsync = promisify(execFile);
const MAX_PROFILE_BYTES = 10 * 1024 * 1024;
const MAX_OPENSSL_DIAGNOSTIC = 500;

function safeDiagnostic(error) {
  const raw = String(error?.stderr || error?.message || error?.code || "unknown");
  return raw
    .replace(/\u001b\[[0-9;]*m/g, "")
    .replace(/\r?\n/g, " ")
    .replace(/(?:[A-Za-z]:)?[\\/][^ ]+/g, "[path]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_OPENSSL_DIAGNOSTIC);
}

function looksLikeBase64Cms(buffer) {
  const text = buffer.toString("ascii").replace(/^\uFEFF/, "").trim();
  if (text.length < 80 || text.length > MAX_PROFILE_BYTES * 2) return false;
  if (!/^[A-Za-z0-9+/=\r\n\t ]+$/.test(text)) return false;
  const compact = text.replace(/\s+/g, "");
  if (compact.length % 4 === 1) return false;
  const padded = compact + "=".repeat((4 - compact.length % 4) % 4);
  const decoded = Buffer.from(padded, "base64");
  return decoded.length >= 32 && decoded[0] === 0x30;
}

function detectInputFormat(buffer) {
  const text = buffer.subarray(0, 512).toString("ascii").replace(/^\uFEFF/, "").trimStart();
  if (/^-----BEGIN (?:CMS|PKCS7|PKCS #7)-----/i.test(text)) return "PEM";
  if (/^(?:MIME-Version:|Content-Type:|Content-Transfer-Encoding:)/i.test(text)) return "SMIME";
  return "DER";
}

function normalizeCmsBytes(buffer) {
  const input = Buffer.from(buffer);
  if (looksLikeBase64Cms(input)) {
    return { buffer: Buffer.from(input.toString("ascii").replace(/\s+/g, ""), "base64"), format: "DER", normalized: "BASE64_DER" };
  }
  return { buffer: input, format: detectInputFormat(input), normalized: "ORIGINAL" };
}

async function verifyCmsPayload(inputBuffer, tempDir, prefix, run) {
  const normalized = normalizeCmsBytes(inputBuffer);
  const inputPath = path.join(tempDir, `${prefix}.cms-input`);
  await fs.writeFile(inputPath, normalized.buffer, { flag: "w", mode: 0o600 });

  const formatOrder = normalized.format === "SMIME"
    ? ["SMIME", "DER", "PEM"]
    : normalized.format === "PEM"
      ? ["PEM", "DER", "SMIME"]
      : ["DER", "PEM", "SMIME"];
  const attempts = [];
  let attemptNo = 0;
  try {
    for (const inform of formatOrder) {
      for (const command of ["cms", "smime"]) {
        attemptNo += 1;
        const outputPath = path.join(tempDir, `${prefix}.verified-${attemptNo}.bin`);
        await fs.rm(outputPath, { force: true });
        const args = command === "cms"
          ? ["cms", "-verify", "-binary", "-inform", inform, "-noverify", "-in", inputPath, "-out", outputPath]
          : ["smime", "-verify", "-binary", "-inform", inform, "-noverify", "-in", inputPath, "-out", outputPath];
        try {
          await run("openssl", args, {
            encoding: "utf8",
            maxBuffer: 1024 * 1024,
            timeout: 30_000,
            windowsHide: true,
          });
          const payload = await fs.readFile(outputPath);
          if (!payload.length || payload.length > MAX_PROFILE_BYTES) {
            throw Object.assign(new Error("CMS payload rỗng hoặc vượt giới hạn kích thước."), { code: "CMS_EMPTY_PAYLOAD" });
          }
          return { payload, attempts, format: inform, command, normalized: normalized.normalized };
        } catch (error) {
          attempts.push({ command, inform, code: error?.code || "CMS_DECODE_FAILED", diagnostic: safeDiagnostic(error) });
        } finally {
          await fs.rm(outputPath, { force: true }).catch(() => {});
        }
      }
    }

    const failure = new Error("OpenSSL không giải mã/xác minh được CMS SignedData của provisioning profile.");
    failure.code = "CMS_DECODE_FAILED";
    failure.attempts = attempts;
    failure.inputFormat = normalized.format;
    throw failure;
  } finally {
    await fs.rm(inputPath, { force: true }).catch(() => {});
  }
}

function getDerEncodedProfileBytes(profile) {
  const value = profile?.["DER-Encoded-Profile"];
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  if (typeof value !== "string") return null;
  const compact = value.replace(/\s+/g, "");
  if (!compact || compact.length % 4 === 1 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return null;
  const padded = compact + "=".repeat((4 - compact.length % 4) % 4);
  const decoded = Buffer.from(padded, "base64");
  return decoded.length >= 32 && decoded[0] === 0x30 ? decoded : null;
}

function readDerOctetString(buffer) {
  const input = Buffer.from(buffer);
  if (input.length < 2 || input[0] !== 0x04) return null;

  let offset = 2;
  const firstLength = input[1];
  let length = 0;
  if (firstLength < 0x80) {
    length = firstLength;
  } else {
    const lengthBytes = firstLength & 0x7f;
    if (lengthBytes === 0 || lengthBytes > 4 || input.length < 2 + lengthBytes) return null;
    for (let index = 0; index < lengthBytes; index += 1) {
      length = (length * 256) + input[offset];
      offset += 1;
    }
    // DER uses the shortest possible length encoding.
    if (length < 0x80 || (lengthBytes > 1 && length < (256 ** (lengthBytes - 1)))) return null;
  }

  if (offset + length !== input.length || length <= 0) return null;
  return input.subarray(offset);
}

function decodeBase64PlistCandidate(buffer) {
  const text = Buffer.from(buffer).toString("ascii").replace(/^\uFEFF/, "").trim();
  if (text.length < 80 || text.length > MAX_PROFILE_BYTES * 2) return null;
  if (!/^[A-Za-z0-9+/=\r\n\t ]+$/.test(text)) return null;
  const compact = text.replace(/\s+/g, "");
  if (compact.length % 4 === 1) return null;
  const decoded = Buffer.from(compact + "=".repeat((4 - compact.length % 4) % 4), "base64");
  if (!decoded.length) return null;
  const signature = decoded.subarray(0, 8).toString("ascii");
  const xml = decoded.subarray(0, 128).toString("utf8").replace(/^\uFEFF/, "").trimStart();
  return signature === "bplist00" || xml.startsWith("<?xml") || xml.startsWith("<plist") || decoded[0] === 0x04
    ? decoded
    : null;
}

function describePlistPayload(buffer) {
  const input = Buffer.from(buffer);
  if (input.subarray(0, 8).toString("ascii") === "bplist00") return "BINARY_PLIST";
  const text = input.subarray(0, 256).toString("utf8").replace(/^\uFEFF/, "").trimStart();
  if (text.startsWith("<?xml") || text.startsWith("<plist")) return "XML_PLIST";
  if (input[0] === 0x04 && readDerOctetString(input)) return "DER_OCTET_STRING";
  if (decodeBase64PlistCandidate(input)) return "BASE64_ENCODED_PLIST";
  if (input[0] === 0x30 && input.indexOf(Buffer.from("06092a864886f70d010702", "hex")) >= 0) return "NESTED_CMS_SIGNED_DATA";
  if (input[0] === 0x30) return "ASN1_DER_SEQUENCE";
  return "UNKNOWN_BINARY_OR_TEXT";
}

function parseProvisioningPlistCandidate(buffer) {
  const input = Buffer.from(buffer);
  const candidates = [];
  const add = (value, format) => {
    if (!value || candidates.some((candidate) => Buffer.isBuffer(value) && Buffer.isBuffer(candidate.value) && value.equals(candidate.value))) return;
    candidates.push({ value, format });
  };

  add(input, describePlistPayload(input));

  // Some CMS producers wrap the signed content in an additional DER OCTET STRING.
  // Unwrap only a complete, definite-length DER value; never strip arbitrary bytes.
  let octet = input;
  for (let depth = 0; depth < 2; depth += 1) {
    const unwrapped = readDerOctetString(octet);
    if (!unwrapped) break;
    add(unwrapped, describePlistPayload(unwrapped));
    octet = unwrapped;
  }

  const base64 = decodeBase64PlistCandidate(input);
  if (base64) add(base64, describePlistPayload(base64));

  let lastError = null;
  for (const candidate of candidates) {
    try {
      if (candidate.format === "XML_PLIST") {
        const xml = Buffer.from(candidate.value).toString("utf8").replace(/^\uFEFF/, "");
        return { profile: parsePlist(xml), format: candidate.format };
      }
      return { profile: parsePlist(new Uint8Array(candidate.value)), format: candidate.format };
    } catch (error) {
      lastError = error;
    }
  }

  const error = new Error("CMS payload was verified, but no supported plist representation could be parsed.");
  error.code = "INVALID_PROVISIONING_PROFILE_PLIST";
  error.payloadFormat = describePlistPayload(input);
  error.payloadBytes = input.length;
  error.cause = lastError || undefined;
  throw error;
}

function validateProfileDictionary(profile) {
  if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
    const error = new Error("CMS đã xác minh nhưng nội dung không phải plist dictionary.");
    error.code = "INVALID_PROVISIONING_PROFILE_PLIST";
    throw error;
  }

  if (!profile.ExpirationDate || !profile.Entitlements || typeof profile.Entitlements !== "object" ||
      !Array.isArray(profile.DeveloperCertificates) || profile.DeveloperCertificates.length === 0) {
    const error = new Error("Plist đã giải mã nhưng thiếu ExpirationDate, Entitlements hoặc DeveloperCertificates.");
    error.code = "INCOMPLETE_PROVISIONING_PROFILE";
    throw error;
  }

  const applicationIdentifier = profile.Entitlements["application-identifier"] ||
    profile.Entitlements["com.apple.application-identifier"];
  if (typeof applicationIdentifier !== "string" || !applicationIdentifier.includes(".")) {
    const error = new Error("Provisioning Profile không có application-identifier hợp lệ.");
    error.code = "INCOMPLETE_PROVISIONING_PROFILE";
    throw error;
  }
}

/**
 * Decode and verify an Apple CMS-wrapped provisioning profile.
 * Supports the normal DER CMS format, PEM, S/MIME, and base64-wrapped DER.
 * If Apple's newer DER-Encoded-Profile field is present, its nested CMS
 * signature is verified too. Unsigned raw plist files are deliberately rejected.
 */
export async function decodeProvisioningProfile(profilePath, options = {}) {
  const run = options.execFileAsync || execFileAsync;
  const readFile = options.readFile || fs.readFile;
  const stat = await fs.stat(profilePath);
  if (!stat.isFile() || stat.size < 32 || stat.size > MAX_PROFILE_BYTES) {
    const error = new Error("File .mobileprovision rỗng hoặc vượt giới hạn 10 MB.");
    error.code = "INVALID_PROVISIONING_PROFILE_SIZE";
    throw error;
  }

  const tempDir = path.dirname(profilePath);
  const input = await readFile(profilePath);
  const inputText = input.subarray(0, 128).toString("utf8").replace(/^\uFEFF/, "").trimStart();
  const looksLikePlainPlist = inputText.startsWith("<?xml") || input.subarray(0, 8).toString("ascii") === "bplist00";
  if (looksLikePlainPlist) {
    const error = new Error("Tệp .mobileprovision là plist thô, không có chữ ký CMS của Apple. Hãy tải profile gốc trực tiếp từ Apple Developer.");
    error.code = "UNSIGNED_PROVISIONING_PROFILE";
    throw error;
  }

  const attemptsSummary = [];
  let decoded;
  try {
    decoded = await verifyCmsPayload(input, tempDir, `profile-${process.pid}-${Date.now()}`, run);
    attemptsSummary.push(...decoded.attempts);
  } catch (error) {
    attemptsSummary.push(...(error.attempts || []));
    console.error("Provisioning profile CMS verification failed:", JSON.stringify({
      profileSize: stat.size,
      inputFormat: error.inputFormat || detectInputFormat(input),
      attempts: attemptsSummary,
    }));
    const wrapped = new Error("Không xác minh được CMS của .mobileprovision. Hãy dùng profile gốc tải từ Apple Developer; nếu vẫn lỗi, kiểm tra Runtime Logs để xem từng phương thức OpenSSL.");
    wrapped.code = "INVALID_PROVISIONING_PROFILE_CMS";
    wrapped.attempts = attemptsSummary;
    throw wrapped;
  }

  let profile;
  let parsedPayloadFormat = "UNKNOWN";
  try {
    const parsed = parseProvisioningPlistCandidate(decoded.payload);
    profile = parsed.profile;
    parsedPayloadFormat = parsed.format;
  } catch (parseError) {
    // If the verified CMS encapsulates another CMS object, verify that inner
    // signature as well before attempting to parse its content. This is a
    // narrowly-scoped compatibility fallback, not a raw ASN.1-to-plist cast.
    const nestedCmsOid = Buffer.from("06092a864886f70d010702", "hex");
    if (parseError.payloadFormat === "NESTED_CMS_SIGNED_DATA" && decoded.payload.indexOf(nestedCmsOid) >= 0) {
      try {
        const nestedCms = await verifyCmsPayload(decoded.payload, tempDir, `profile-inner-${process.pid}-${Date.now()}`, run);
        const nestedParsed = parseProvisioningPlistCandidate(nestedCms.payload);
        profile = nestedParsed.profile;
        parsedPayloadFormat = `NESTED_CMS_${nestedParsed.format}`;
      } catch (nestedError) {
        console.error("Provisioning profile payload parse failed:", JSON.stringify({
          profileSize: stat.size,
          payloadSize: decoded.payload.length,
          payloadFormat: parseError.payloadFormat || describePlistPayload(decoded.payload),
          nestedPayloadFormat: nestedError?.payloadFormat || describePlistPayload(nestedError?.payload || Buffer.alloc(0)),
          nestedErrorCode: nestedError?.code || "NESTED_CMS_DECODE_FAILED",
          diagnostic: safeDiagnostic(nestedError),
        }));
        const error = new Error(`CMS đã xác minh nhưng payload không phải plist được hỗ trợ (dạng ${parseError.payloadFormat || "không nhận diện"}, ${decoded.payload.length} byte). Nếu đây là profile Apple hợp lệ, cần kiểm tra tệp .mobileprovision gốc.`);
        error.code = "INVALID_PROVISIONING_PROFILE_PLIST";
        error.cause = nestedError;
        throw error;
      }
    } else {
      console.error("Provisioning profile payload parse failed:", JSON.stringify({
        profileSize: stat.size,
        payloadSize: decoded.payload.length,
        payloadFormat: parseError.payloadFormat || describePlistPayload(decoded.payload),
        parserDiagnostic: safeDiagnostic(parseError.cause || parseError),
      }));
      const error = new Error(`CMS đã xác minh nhưng payload không phải plist được hỗ trợ (dạng ${parseError.payloadFormat || "không nhận diện"}, ${decoded.payload.length} byte).`);
      error.code = "INVALID_PROVISIONING_PROFILE_PLIST";
      error.cause = parseError;
      throw error;
    }
  }
  validateProfileDictionary(profile);

  // Apple TN3125 documents a newer nested DER-Encoded-Profile CMS payload.
  // Verify it when present so modern iOS profiles aren't accepted on the
  // strength of the legacy plist alone. Keep the outer profile for ZSign.
  const nestedDerProfile = getDerEncodedProfileBytes(profile);
  if (profile["DER-Encoded-Profile"] != null && !nestedDerProfile) {
    const error = new Error("Trường DER-Encoded-Profile của profile không phải Base64 DER hợp lệ.");
    error.code = "INVALID_DER_ENCODED_PROFILE";
    throw error;
  }
  if (nestedDerProfile) {
    try {
      const nested = await verifyCmsPayload(nestedDerProfile, tempDir, `profile-der-${process.pid}-${Date.now()}`, run);
      // The inner content is ASN.1 DER, not an XML plist. Ask OpenSSL to parse
      // it structurally; this catches truncated or malformed nested payloads.
      const asn1Path = path.join(tempDir, `profile-der-${process.pid}-${Date.now()}.asn1`);
      await fs.writeFile(asn1Path, nested.payload, { mode: 0o600 });
      try {
        await run("openssl", ["asn1parse", "-inform", "DER", "-in", asn1Path, "-noout"], {
          encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 15_000, windowsHide: true,
        });
      } finally {
        await fs.rm(asn1Path, { force: true }).catch(() => {});
      }
      console.info("Provisioning profile nested DER payload verified:", JSON.stringify({
        format: nested.format,
        command: nested.command,
        normalized: nested.normalized,
      }));
    } catch (cause) {
      console.error("Provisioning profile DER-Encoded-Profile verification failed:", JSON.stringify({
        attempts: cause?.attempts || [],
        code: cause?.code || "DER_PROFILE_VERIFY_FAILED",
        diagnostic: safeDiagnostic(cause),
      }));
      const error = new Error("Profile có DER-Encoded-Profile nhưng chữ ký CMS hoặc cấu trúc DER bên trong không hợp lệ.");
      error.code = "INVALID_DER_ENCODED_PROFILE";
      error.cause = cause;
      throw error;
    }
  }

  console.info("Provisioning profile decoded:", JSON.stringify({
    profileSize: stat.size,
    cmsCommand: decoded.command,
    cmsFormat: decoded.format,
    normalizedInput: decoded.normalized,
    parsedPayloadFormat,
    nestedDerProfile: Boolean(nestedDerProfile),
    developerCertificateCount: profile.DeveloperCertificates.length,
    hasApplicationIdentifier: true,
  }));
  return profile;
}
