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
    .replace(/(?:[A-Za-z]:)?[\/][^ ]+/g, "[path]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, MAX_OPENSSL_DIAGNOSTIC);
}

/**
 * Decode Apple's CMS-wrapped provisioning profile. The CMS signature is
 * integrity-checked by OpenSSL (-noverify skips only certificate-chain trust
 * validation; it does not skip the SignedData content-signature check).
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

  const payloadPath = path.join(path.dirname(profilePath), `${path.basename(profilePath)}.${process.pid}.${Date.now()}.decoded.plist`);
  const input = await readFile(profilePath);
  const isPem = input.subarray(0, 64).toString("ascii").trimStart().startsWith("-----BEGIN");
  const formats = isPem ? ["PEM", "DER"] : ["DER", "PEM"];
  const attempts = [];

  try {
    for (const inform of formats) {
      // `cms` is the primary CMS SignedData decoder. `smime` is a compatibility
      // fallback for OpenSSL builds with different command/provider behavior.
      for (const command of ["cms", "smime"]) {
        await fs.rm(payloadPath, { force: true });
        const args = command === "cms"
          ? ["cms", "-verify", "-binary", "-inform", inform, "-noverify", "-in", profilePath, "-out", payloadPath]
          : ["smime", "-verify", "-binary", "-inform", inform, "-noverify", "-in", profilePath, "-out", payloadPath];
        try {
          await run("openssl", args, { encoding: "utf8", maxBuffer: 1024 * 1024, timeout: 30_000, windowsHide: true });
          const payload = await readFile(payloadPath);
          if (!payload.length || payload.length > MAX_PROFILE_BYTES) {
            throw new Error("CMS payload rỗng hoặc vượt giới hạn kích thước.");
          }

          let profile;
          try {
            profile = parsePlist(new Uint8Array(payload));
          } catch (parseError) {
            const error = new Error("Chữ ký CMS đọc được nhưng dữ liệu bên trong không phải plist hợp lệ.");
            error.code = "INVALID_PROVISIONING_PROFILE_PLIST";
            error.cause = parseError;
            throw error;
          }

          if (!profile || typeof profile !== "object" || Array.isArray(profile)) {
            const error = new Error("Provisioning Profile không chứa plist dictionary hợp lệ.");
            error.code = "INVALID_PROVISIONING_PROFILE_PLIST";
            throw error;
          }

          if (!profile.ExpirationDate || !profile.Entitlements || !Array.isArray(profile.DeveloperCertificates)) {
            const error = new Error("Plist đã giải mã nhưng thiếu trường bắt buộc của Provisioning Profile Apple.");
            error.code = "INCOMPLETE_PROVISIONING_PROFILE";
            throw error;
          }

          return profile;
        } catch (error) {
          // Do not turn a successfully decoded but malformed plist into another
          // CMS attempt; preserve the precise validation error.
          if (["INVALID_PROVISIONING_PROFILE_PLIST", "INCOMPLETE_PROVISIONING_PROFILE"].includes(error?.code)) throw error;
          attempts.push({ command, inform, code: error?.code || "CMS_DECODE_FAILED", diagnostic: safeDiagnostic(error) });
        }
      }
    }

    const looksLikePlist = input.subarray(0, 128).toString("utf8").trimStart().startsWith("<?xml")
      || input.subarray(0, 8).toString("ascii") === "bplist00";
    const wrapped = new Error(looksLikePlist
      ? "File .mobileprovision có vẻ là plist thô, không có lớp chữ ký CMS của Apple. Hãy dùng file .mobileprovision tải trực tiếp từ Apple Developer."
      : "Không xác minh/giải mã được chữ ký CMS của .mobileprovision. File có thể bị hỏng, bị đổi định dạng hoặc không phải provisioning profile Apple.");
    wrapped.code = "INVALID_PROVISIONING_PROFILE_CMS";
    wrapped.attempts = attempts;
    console.error("Provisioning profile CMS decode failed:", JSON.stringify({
      profileSize: stat.size,
      inputFormat: isPem ? "PEM" : "DER_OR_UNKNOWN",
      attempts,
    }));
    throw wrapped;
  } finally {
    await fs.rm(payloadPath, { force: true }).catch(() => {});
  }
}
