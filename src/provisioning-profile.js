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
  try {
    profile = parsePlist(new Uint8Array(decoded.payload));
  } catch (parseError) {
    const error = new Error("CMS đã xác minh thành công nhưng payload bên trong không phải XML/binary plist mà Worker hỗ trợ.");
    error.code = "INVALID_PROVISIONING_PROFILE_PLIST";
    error.cause = parseError;
    throw error;
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
    nestedDerProfile: Boolean(nestedDerProfile),
    developerCertificateCount: profile.DeveloperCertificates.length,
    hasApplicationIdentifier: true,
  }));
  return profile;
}
