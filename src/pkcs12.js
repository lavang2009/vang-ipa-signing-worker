import fs from "node:fs/promises";
import crypto from "node:crypto";
import path from "node:path";
import { spawn } from "node:child_process";

const OPENSSL_TIMEOUT_MS = 30_000;

function runOpenSsl(args, password) {
  return new Promise((resolve, reject) => {
    const child = spawn("openssl", args, {
      stdio: ["pipe", "ignore", "pipe"],
      windowsHide: true,
    });
    let stderr = "";
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(reject, Object.assign(new Error("OpenSSL PKCS#12 inspection timed out."), { code: "PKCS12_TIMEOUT" }));
    }, OPENSSL_TIMEOUT_MS);

    child.on("error", (error) => finish(reject, error));
    child.stderr.on("data", (chunk) => {
      if (stderr.length < 4_000) stderr += chunk.toString();
    });
    child.on("close", (code, signal) => finish(resolve, { ok: code === 0, code, signal, stderr }));
    child.stdin.on("error", () => {});
    child.stdin.end(Buffer.from(`${password}\n`, "utf8"));
  });
}

function invalidPkcs12(cause) {
  const error = new Error(
    "Không giải mã được tệp P12/PFX. Hãy kiểm tra đúng định dạng PKCS#12 và mật khẩu; nếu tệp không có mật khẩu, hãy để trống.",
  );
  error.code = "INVALID_PKCS12";
  error.cause = cause;
  return error;
}

/**
 * Keep normal PKCS#12 files unchanged. If OpenSSL 3 rejects an older P12/PFX
 * because it uses a legacy cipher, decode it with the legacy provider and
 * re-export it using OpenSSL's current defaults for ZSign.
 */
export async function preparePkcs12ForSigning(inputPath, workDir, password) {
  const passphrase = String(password || "");
  if (passphrase.includes("\0")) throw invalidPkcs12(new Error("Unsupported password encoding."));

  const standard = await runOpenSsl([
    "pkcs12", "-in", inputPath, "-noout", "-passin", "fd:0",
  ], passphrase);
  if (standard.ok) return inputPath;

  const extractedPath = path.join(workDir, "signing-cert-normalize.pem");
  const normalizedPath = path.join(workDir, "signing-cert-normalized.p12");
  try {
    const legacy = await runOpenSsl([
      "pkcs12", "-legacy", "-in", inputPath, "-nodes", "-passin", "fd:0", "-out", extractedPath,
    ], passphrase);
    if (!legacy.ok) throw invalidPkcs12(new Error(legacy.stderr || standard.stderr));
    await fs.chmod(extractedPath, 0o600);

    const extracted = await fs.readFile(extractedPath, "utf8");
    if (!/-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/.test(extracted)) {
      throw invalidPkcs12(new Error("PKCS#12 file does not contain a private signing key."));
    }

    const exported = await runOpenSsl([
      "pkcs12", "-export", "-in", extractedPath, "-out", normalizedPath, "-passout", "fd:0",
    ], passphrase);
    if (!exported.ok) throw invalidPkcs12(new Error(exported.stderr));

    const stat = await fs.stat(normalizedPath);
    if (!stat.isFile() || stat.size < 32) throw invalidPkcs12(new Error("Normalized PKCS#12 output is empty."));
    await fs.chmod(normalizedPath, 0o600);
    console.info("Legacy PKCS#12 signing file normalized:", JSON.stringify({ converted: true }));
    return normalizedPath;
  } catch (error) {
    if (error?.code === "INVALID_PKCS12") throw error;
    throw invalidPkcs12(error);
  } finally {
    await fs.rm(extractedPath, { force: true }).catch(() => {});
  }
}

/** Extract only public certificates from PKCS#12 and return SHA-256 DER
 * fingerprints. The private key is never written to stdout or returned. */
export async function getPkcs12CertificateFingerprints(p12Path, password = "") {
  const passphrase = String(password || "");
  if (passphrase.includes("\0")) throw invalidPkcs12(new Error("Unsupported password encoding."));

  const pem = await new Promise((resolve, reject) => {
    const child = spawn("openssl", [
      "pkcs12", "-in", p12Path, "-clcerts", "-nokeys", "-passin", "fd:0",
    ], { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    const stdout = [];
    let stdoutBytes = 0;
    let stderr = "";
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(reject, Object.assign(new Error("OpenSSL PKCS#12 certificate inspection timed out."), { code: "PKCS12_TIMEOUT" }));
    }, OPENSSL_TIMEOUT_MS);

    child.stdout.on("data", (chunk) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > 2 * 1024 * 1024) {
        child.kill("SIGKILL");
        finish(reject, invalidPkcs12(new Error("PKCS#12 certificate output exceeded the inspection limit.")));
        return;
      }
      stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      if (stderr.length < 4_000) stderr += chunk.toString();
    });
    child.on("error", (error) => finish(reject, error));
    child.on("close", (code) => {
      if (code !== 0) {
        finish(reject, invalidPkcs12(new Error(stderr || `OpenSSL exited with code ${code}.`)));
        return;
      }
      finish(resolve, Buffer.concat(stdout).toString("utf8"));
    });
    child.stdin.on("error", () => {});
    child.stdin.end(Buffer.from(`${passphrase}\n`, "utf8"));
  });

  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  const fingerprints = [];
  for (const block of blocks) {
    try {
      const certificate = new crypto.X509Certificate(block);
      fingerprints.push(crypto.createHash("sha256").update(certificate.raw).digest("hex"));
    } catch {
      // Ignore non-certificate blocks; only usable X.509 DER certs are compared.
    }
  }
  if (!fingerprints.length) {
    const error = new Error("P12/PFX không chứa chứng chỉ X.509 công khai có thể đọc được.");
    error.code = "SIGNING_CERTIFICATE_EXTRACTION_FAILED";
    throw error;
  }
  return [...new Set(fingerprints)];
}

