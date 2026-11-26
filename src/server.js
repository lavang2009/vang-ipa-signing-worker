import crypto from "node:crypto";
import fs from "node:fs/promises";
import { createReadStream, createWriteStream } from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawn } from "node:child_process";
import { Readable } from "node:stream";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { pipeline } from "node:stream/promises";
import express from "express";
import multer from "multer";
import { cert, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import { parseIpaInfoPlist } from "./ipa-info-plist.js";
import { decodeProvisioningProfile } from "./provisioning-profile.js";
import { preparePkcs12ForSigning } from "./pkcs12.js";
import { applyCors, buildAllowedOrigins } from "./cors.js";
import { isIpaSigningMaintenanceBlocked, normalizeIpaSigningMaintenance } from "./maintenance.js";
import {
  assertProvisioningProfileUsable,
  assertTargetDeviceAllowed,
  assertBundleIdentifierAllowed,
  buildItmsServicesUrl,
  buildOtaManifestXml,
  classifyProvisioningProfile,
  isSupportedUdid,
} from "./ios-distribution.js";
import { del, get, issueSignedToken, presignUrl, put } from "@vercel/blob";

const execFileAsync = promisify(execFile);
const app = express();
const port = Number(process.env.PORT || 8080);
const maxIpaBytes = Number(process.env.SIGNING_MAX_IPA_BYTES || 512 * 1024 * 1024);
const maxCredentialFileBytes = Number(process.env.SIGNING_MAX_CREDENTIAL_FILE_BYTES || process.env.SIGNING_MAX_CERT_ZIP_BYTES || 20 * 1024 * 1024);
const maxProfileFileBytes = Number(process.env.SIGNING_MAX_PROFILE_FILE_BYTES || 10 * 1024 * 1024);
const dailyLimit = Number(process.env.SIGNING_DAILY_LIMIT || 10);
const signingTimeout = Number(process.env.SIGNING_TIMEOUT_MS || 240_000);
const zsignBin = process.env.ZSIGN_BIN || "/usr/local/bin/zsign";
const blobReady = Boolean(process.env.BLOB_READ_WRITE_TOKEN);
const workerBuild = "ipa-signing-bundle-id-profile-match-fix-2026-11-26";

// Keep the CORS allow-list strict and independently unit-tested.
const allowedOrigins = buildAllowedOrigins(process.env.ALLOWED_ORIGINS || "");

function initFirebase() {
  if (getApps().length) return getApps()[0];
  let account = null;
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    account = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    if (typeof account.private_key === "string") {
      account.private_key = account.private_key.replace(/\\n/g, "\n");
    }
  } else if (process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL && process.env.FIREBASE_PRIVATE_KEY) {
    account = {
      project_id: process.env.FIREBASE_PROJECT_ID,
      client_email: process.env.FIREBASE_CLIENT_EMAIL,
      private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    };
  }
  if (!account) throw new Error("Firebase Admin chưa được cấu hình cho signing worker.");
  return initializeApp({ credential: cert(account), projectId: account.project_id || process.env.FIREBASE_PROJECT_ID });
}

let firebaseReady = false;
let firebaseProjectId = null;
try {
  const firebaseApp = initFirebase();
  firebaseProjectId = firebaseApp.options.projectId || process.env.FIREBASE_PROJECT_ID || null;
  firebaseReady = true;
}
catch (error) { console.error("Firebase Admin initialization failed:", error instanceof Error ? error.message : "unknown"); }
let zsignReady = false;
let zsignVersion = null;
let zsignError = null;
try {
  await fs.access(zsignBin, 0o1);
  const versionResult = await execFileAsync(zsignBin, ["--version"], { encoding: "utf8", timeout: 10_000 });
  zsignVersion = String(versionResult.stdout || versionResult.stderr || "").trim().slice(0, 100) || "available";
  zsignReady = true;
} catch (error) {
  zsignError = error?.code || "STARTUP_CHECK_FAILED";
  console.error("ZSign engine is unavailable:", zsignError, error instanceof Error ? error.message : "unknown");
}
let opensslReady = false;
let opensslVersion = null;
try {
  const result = await execFileAsync("openssl", ["version"], { encoding: "utf8", timeout: 5_000 });
  opensslVersion = String(result.stdout || "").trim().slice(0, 100);
  opensslReady = Boolean(opensslVersion);
} catch (error) {
  console.error("OpenSSL profile decoder is unavailable:", error?.code || "STARTUP_CHECK_FAILED");
}

app.use((req, res, next) => {
  // A request ID lets the browser error be matched to one safe runtime-log entry.
  // Never log request bodies, Authorization headers, or certificate passwords.
  req.requestId = crypto.randomUUID();
  res.setHeader("X-Request-ID", req.requestId);
  next();
});

app.use((req, res, next) => {
  // Server-to-server requests without an Origin remain supported. Browser requests
  // must match the exact allow-list and receive the headers required for Bearer auth.
  if (!applyCors(req, res, allowedOrigins)) {
    return res.status(403).json({ error: "Origin này không được phép sử dụng signing worker.", requestId: req.requestId });
  }
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// The browser sends only small JSON metadata to the worker; large files move directly through Blob.
app.use(express.json({ limit: "64kb" }));

app.get("/", (_req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json({
    service: "VANG STORE IPA Signing Worker",
    status: firebaseReady && zsignReady && blobReady && opensslReady ? "ready" : "not_ready",
    health: "/healthz",
    signingEndpoint: "POST /v1/sign-blob",
    engine: zsignReady ? "zsign" : "unavailable",
  });
});

app.get("/healthz", (_req, res) => {
  const ready = firebaseReady && zsignReady && blobReady && opensslReady;
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.status(ready ? 200 : 503).json({
    ok: ready,
    service: "VANG STORE IPA Signing Worker",
    build: workerBuild,
    engine: zsignReady ? "zsign" : "unavailable",
    firebase: firebaseReady,
    firebaseProjectId,
    zsign: zsignReady,
    blob: blobReady,
    openssl: opensslReady,
    opensslVersion,
    provisioningProfileInspector: opensslReady,
    signBlob: true,
    maintenanceControl: true,
    corsConfigured: allowedOrigins.size > 0,
    allowedOriginCount: allowedOrigins.size,
    signingEndpoint: "POST /v1/sign-blob",
    ...(zsignReady ? { zsignVersion } : { zsignError }),
  });
});

async function hasAdminAccess(user) {
  if (user?.admin === true) return true;
  const adminEmails = (process.env.ADMIN_EMAILS || "").split(",").map((email) => email.trim().toLowerCase()).filter(Boolean);
  if (user?.email && adminEmails.includes(String(user.email).toLowerCase())) return true;
  const snapshot = await getFirestore().collection("users").doc(user.uid).get();
  return snapshot.exists && snapshot.get("role") === "admin";
}

async function authenticate(req, res, next) {
  try {
    if (!firebaseReady) return res.status(503).json({ error: "Signing worker chưa cấu hình Firebase Admin." });
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) return res.status(401).json({ error: "Bạn cần đăng nhập để sử dụng công cụ ký IPA." });
    req.user = await getAuth().verifyIdToken(match[1], true);
    try { req.isAdmin = await hasAdminAccess(req.user); } catch { req.isAdmin = false; }
    next();
  } catch {
    res.status(401).json({ error: "Phiên đăng nhập không hợp lệ hoặc đã hết hạn. Hãy đăng nhập lại." });
  }
}

async function enforceIpaSigningMaintenance(req, res, next) {
  try {
    const snapshot = await getFirestore().collection("siteSettings").doc("ipaSigningMaintenance").get();
    const maintenance = normalizeIpaSigningMaintenance(snapshot.exists ? snapshot.data() || {} : {});
    if (isIpaSigningMaintenanceBlocked(maintenance, req.isAdmin === true)) {
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Retry-After", "60");
      return res.status(503).json({
        error: maintenance.message,
        maintenance: true,
        title: maintenance.title,
        estimatedReturn: maintenance.estimatedReturn,
        code: "IPA_SIGNING_MAINTENANCE",
        requestId: req.requestId,
      });
    }
    return next();
  } catch (error) {
    // Fail closed: signing must not continue if the maintenance state cannot be checked.
    console.error("IPA signing maintenance state check failed:", JSON.stringify({
      requestId: req.requestId || null,
      code: error?.code || null,
      message: error instanceof Error ? error.message : "unknown",
    }));
    return res.status(503).json({
      error: "Không thể xác minh trạng thái dịch vụ ký IPA. Yêu cầu ký mới đang tạm khóa; vui lòng thử lại sau.",
      maintenance: true,
      code: "IPA_SIGNING_STATUS_UNAVAILABLE",
      requestId: req.requestId,
    });
  }
}

async function createWorkDir(req, _res, next) {
  // Some container revisions expose a custom TMPDIR that may not be writable.
  // Try the configured directory first, then Node's default temp directory and
  // finally /tmp. Every work directory is unique and private (mode 0700).
  const candidates = [...new Set([
    process.env.SIGNING_TMPDIR,
    os.tmpdir(),
    "/tmp",
  ].filter((value) => typeof value === "string" && value.trim()))];

  let lastError = null;
  for (const baseDir of candidates) {
    try {
      await fs.mkdir(baseDir, { recursive: true, mode: 0o700 });
      req.workDir = await fs.mkdtemp(path.join(baseDir, "vang-sign-"));
      await fs.chmod(req.workDir, 0o700);
      console.info("Signing work directory created:", JSON.stringify({
        requestId: req.requestId || null,
        tempBase: baseDir,
      }));
      return next();
    } catch (error) {
      lastError = error;
      console.error("Signing temp directory unavailable:", JSON.stringify({
        requestId: req.requestId || null,
        tempBase: baseDir,
        code: error?.code || null,
        message: error instanceof Error ? error.message : "unknown",
      }));
    }
  }

  const error = new Error("Không thể tạo vùng làm việc tạm thời trên signing worker.");
  error.code = "WORKDIR_UNAVAILABLE";
  error.cause = lastError || undefined;
  return next(error);
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, _file, callback) => callback(null, req.workDir),
    filename: (_req, file, callback) => callback(null, `${crypto.randomUUID()}${path.extname(file.originalname).toLowerCase()}`),
  }),
  limits: { files: 3, fields: 8, fileSize: maxIpaBytes, fieldSize: 4096 },
});

function safeInputName(value, fallback, extension) {
  const base = path.basename(String(value || fallback)).replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 90);
  return base.toLowerCase().endsWith(extension) ? base : `${base}${extension}`;
}

// ZIP inspection is retained only for the IPA app bundle itself. Signing credentials are uploaded as standalone P12/PFX and .mobileprovision files.
async function getZipEntries(filePath, maxBuffer = 3 * 1024 * 1024) {
  let result;
  try {
    result = await execFileAsync("unzip", ["-Z1", filePath], { encoding: "utf8", maxBuffer, timeout: 30_000 });
  } catch {
    throw new Error("Không đọc được cấu trúc ZIP. Kiểm tra file có bị lỗi hoặc được đặt mật khẩu ZIP hay không.");
  }
  const entries = result.stdout.split(/\r?\n/).filter(Boolean);
  if (!entries.length) throw new Error("ZIP không có dữ liệu hoặc không phải file ZIP hợp lệ.");
  return entries;
}

async function readIpaAppMetadata(ipaPath) {
  const entries = await getZipEntries(ipaPath, 8 * 1024 * 1024);
  const infoEntries = entries.filter((entry) => /^Payload\/[^/]+\.app\/Info\.plist$/i.test(entry.replace(/^\.\//, "")));
  if (infoEntries.length !== 1) {
    throw new Error("IPA phải có đúng một Payload/*.app/Info.plist để tạo liên kết cài đặt iOS.");
  }

  const result = await execFileAsync("unzip", ["-p", ipaPath, infoEntries[0]], {
    encoding: null,
    maxBuffer: 8 * 1024 * 1024,
    timeout: 30_000,
  });
  const parsedInfo = parseIpaInfoPlist(result.stdout);
  const metadata = parsedInfo.value;
  const bundleIdentifier = String(metadata?.CFBundleIdentifier || "").trim();
  const bundleVersion = String(metadata?.CFBundleVersion || metadata?.CFBundleShortVersionString || "").trim();
  const title = String(metadata?.CFBundleDisplayName || metadata?.CFBundleName || "iOS App").trim();
  if (!bundleIdentifier || !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleIdentifier)) {
    throw new Error("Không đọc được Bundle ID hợp lệ từ Info.plist của IPA đã ký.");
  }
  if (!bundleVersion) throw new Error("Không đọc được phiên bản CFBundleVersion từ Info.plist của IPA.");
  return { bundleIdentifier, bundleVersion, title };
}

function assertSignedBundleIdentifier(expectedBundleIdentifier, actualBundleIdentifier) {
  if (actualBundleIdentifier === expectedBundleIdentifier) return;
  const error = new Error(
    `Bundle ID sau khi ZSign xử lý là "${actualBundleIdentifier || "(không đọc được)"}", nhưng Bundle ID được chọn trước khi ký là "${expectedBundleIdentifier}". Kết quả đã bị hủy; hãy kiểm tra IPA đầu vào và tùy chọn đổi Bundle ID.`,
  );
  error.code = "BUNDLE_ID_NOT_APPLIED";
  error.details = { expectedBundleIdentifier, actualBundleIdentifier: actualBundleIdentifier || null };
  throw error;
}

async function ensureZipMagic(filePath, label) {
  const handle = await fs.open(filePath, "r");
  try {
    const buffer = Buffer.alloc(4);
    const { bytesRead } = await handle.read(buffer, 0, 4, 0);
    if (bytesRead < 4 || buffer[0] !== 0x50 || buffer[1] !== 0x4b) throw new Error(`${label} không phải ZIP hợp lệ hoặc tệp đã hỏng.`);
  } finally { await handle.close(); }
}

async function assertIpaStructure(filePath) {
  await ensureZipMagic(filePath, "IPA");
  const entries = await getZipEntries(filePath, 8 * 1024 * 1024);
  const hasInfo = entries.some((entry) => /^Payload\/[^/]+\.app\/Info\.plist$/i.test(entry));
  if (!hasInfo) throw new Error("Không tìm thấy Payload/*.app/Info.plist. File này không có cấu trúc IPA chuẩn.");
}

async function consumeDailyQuota(uid) {
  const db = getFirestore();
  const date = new Date().toISOString().slice(0, 10);
  const ref = db.collection("ipaSigningQuotas").doc(`${uid}_${date}`);
  await db.runTransaction(async (transaction) => {
    const snap = await transaction.get(ref);
    const used = Number(snap.exists ? snap.get("count") || 0 : 0);
    if (used >= dailyLimit) throw new Error("Bạn đã đạt giới hạn ký IPA trong ngày. Vui lòng thử lại vào ngày mai.");
    transaction.set(ref, { uid, date, count: used + 1, updatedAt: FieldValue.serverTimestamp() }, { merge: true });
  });
}

async function writeAudit(uid, status, details = {}) {
  try {
    await getFirestore().collection("ipaSigningJobs").add({
      uid,
      status,
      ipaSize: Number(details.ipaSize || 0),
      credentialFilesBytes: Number(details.p12Size || 0) + Number(details.profileSize || 0),
      p12Size: Number(details.p12Size || 0),
      profileSize: Number(details.profileSize || 0),
      bundleIdChanged: Boolean(details.bundleIdChanged),
      appNameChanged: Boolean(details.appNameChanged),
      durationMs: Number(details.durationMs || 0),
      errorCode: details.errorCode || null,
      requestId: details.requestId || null,
      createdAt: FieldValue.serverTimestamp(),
    });
  } catch (error) {
    console.error("Could not write signing audit event:", error instanceof Error ? error.message : "unknown");
  }
}

function runZSign(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(zsignBin, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), signingTimeout);
    child.stdout.on("data", (chunk) => { if (stdout.length < 60_000) stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { if (stderr.length < 60_000) stderr += chunk.toString(); });
    child.on("error", (error) => { clearTimeout(timer); reject(error); });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (code === 0) resolve({ stdout, stderr });
      else {
        const message = `${stderr}\n${stdout}`.slice(0, 6000);
        const error = new Error(message.trim() || (signal ? `Signing process stopped (${signal}).` : `ZSign exited with code ${code}.`));
        error.code = signal === "SIGKILL" ? "SIGNING_TIMEOUT" : "SIGNING_FAILED";
        reject(error);
      }
    });
  });
}

function friendlySigningError(error) {
  const raw = error instanceof Error ? error.message : String(error || "");
  const lower = raw.toLowerCase();
  if (raw.startsWith("Bạn đã đạt giới hạn ký IPA")) return raw;
  if (error?.code === "BLOB_NOT_FOUND") return raw;
  if (error?.code === "SIGNING_TIMEOUT") return "Quá thời gian ký IPA. Hãy thử IPA nhỏ hơn hoặc liên hệ quản trị viên kiểm tra worker.";
  if (error?.code === "SIGNING_FAILED") {
    if (/mac verify error|password|pkcs12|bad decrypt|unable to load private key/.test(lower)) return "ZSign không giải mã được P12/PFX. Hãy kiểm tra mật khẩu; nếu không đặt mật khẩu thì để trống. Worker đã tự chuyển đổi P12 dùng mã hóa PKCS#12 cũ khi có thể.";
    if (/provision|profile|entitlement|bundle identifier|application-identifier/.test(lower)) return "Provisioning Profile đã được giải mã, nhưng ZSign từ chối ký với cặp chứng chỉ/profile hoặc Bundle ID này. Dùng chứng chỉ có khóa riêng được liệt kê trong DeveloperCertificates của profile và kiểm tra App ID/entitlements.";
    return "ZSign không thể ký IPA này. Hãy kiểm tra chứng chỉ còn hạn, profile phù hợp và thử lại bằng bộ tệp hợp lệ.";
  }
  if (error?.code === "INVALID_PROVISIONING_PROFILE_CMS") return `${raw} (Mã: INVALID_PROVISIONING_PROFILE_CMS). Worker đã thử CMS DER, PEM và S/MIME; xem Runtime Logs để biết lỗi OpenSSL cụ thể.`;
  if (error?.code === "INVALID_DER_ENCODED_PROFILE") return `${raw} (Mã: INVALID_DER_ENCODED_PROFILE). Phần DER-Encoded-Profile của profile không hợp lệ hoặc không xác minh được.`;
  if (error?.code === "UNSIGNED_PROVISIONING_PROFILE") return `${raw} (Mã: UNSIGNED_PROVISIONING_PROFILE). Worker chỉ chấp nhận profile CMS gốc đã được Apple ký.`;
  if (error?.code === "INVALID_PROVISIONING_PROFILE_PLIST") return `${raw} (Mã: INVALID_PROVISIONING_PROFILE_PLIST). Worker đã thử XML, Binary plist, Base64 plist và lớp DER OCTET STRING hợp lệ; kiểm tra Runtime Logs theo mã yêu cầu để biết định dạng payload thực tế.`;
  if (error?.code === "INCOMPLETE_PROVISIONING_PROFILE") return `${raw} (Mã: INCOMPLETE_PROVISIONING_PROFILE). Profile thiếu trường bắt buộc; hãy tải lại từ Apple Developer.`;
  if (error?.code === "INVALID_PROVISIONING_PROFILE_SIZE") return raw;
  if (error?.code === "INVALID_IPA_INFO_PLIST") return `${raw} (Mã: INVALID_IPA_INFO_PLIST). Worker không đọc được Payload/*.app/Info.plist sau khi ký; hỗ trợ XML, Binary plist và OpenStep. Hãy kiểm tra IPA đầu vào hoặc cấu trúc IPA đầu ra.`;
  if (error?.code === "BUNDLE_ID_PROFILE_MISMATCH") return raw;
  if (error?.code === "BUNDLE_ID_NOT_APPLIED") return `${raw} (Mã: BUNDLE_ID_NOT_APPLIED). ZSign không tạo ra Bundle ID đúng như yêu cầu; Worker đã hủy kết quả để tránh trả về IPA không tương thích profile.`;
  if (error?.code === "INVALID_PKCS12") return raw;
  if (error?.code === "PKCS12_TIMEOUT") return "Quá thời gian đọc P12/PFX. Hãy thử lại hoặc kiểm tra tệp chứng chỉ.";
  if (error?.code === "ENOENT") return "Signing worker thiếu chương trình unzip, OpenSSL hoặc ZSign. Hãy liên hệ quản trị viên.";
  return raw || "Không thể xử lý tệp ký IPA.";
}

app.post("/v1/sign", authenticate, enforceIpaSigningMaintenance, createWorkDir, upload.fields([{ name: "ipa", maxCount: 1 }, { name: "p12", maxCount: 1 }, { name: "profile", maxCount: 1 }]), async (req, res, next) => {
  const startedAt = Date.now();
  let auditCode = "UNKNOWN";
  const files = req.files || {};
  const ipa = files.ipa?.[0];
  const p12 = files.p12?.[0];
  const profile = files.profile?.[0];
  try {
    if (!ipa || !p12 || !profile) throw new Error("Vui lòng tải lên IPA, chứng chỉ P12/PFX và Provisioning Profile.");
    if (!ipa.originalname.toLowerCase().endsWith(".ipa")) throw new Error("File ứng dụng phải có đuôi .ipa.");
    if (!/\.(p12|pfx)$/i.test(p12.originalname)) throw new Error("Chứng chỉ phải là tệp .p12 hoặc .pfx.");
    if (!profile.originalname.toLowerCase().endsWith(".mobileprovision")) throw new Error("Hồ sơ ký phải là tệp .mobileprovision.");
    if (ipa.size > maxIpaBytes) throw new Error(`IPA vượt giới hạn ${Math.floor(maxIpaBytes / 1024 / 1024)} MB.`);
    if (p12.size > maxCredentialFileBytes) throw new Error(`P12/PFX vượt giới hạn ${Math.floor(maxCredentialFileBytes / 1024 / 1024)} MB.`);
    if (profile.size > maxProfileFileBytes) throw new Error(`Provisioning Profile vượt giới hạn ${Math.floor(maxProfileFileBytes / 1024 / 1024)} MB.`);
    const p12Password = String(req.body.p12Password || "");
    const bundleId = String(req.body.bundleId || "").trim();
    const appName = String(req.body.appName || "").trim();
    const targetUdid = String(req.body.targetUdid || "").trim().toUpperCase();
    if (bundleId && (bundleId.length > 180 || !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId))) throw new Error("Bundle ID không đúng định dạng.");
    if (appName.length > 100) throw new Error("Tên ứng dụng không được dài quá 100 ký tự.");
    if (targetUdid && !isSupportedUdid(targetUdid)) {
      const error = new Error("UDID phải có 40 ký tự hexadecimal hoặc 25 ký tự dạng 8-16.");
      error.code = "INVALID_TARGET_UDID";
      throw error;
    }

    await assertIpaStructure(ipa.path);
    const sourceMetadata = await readIpaAppMetadata(ipa.path);
    const signingP12Path = await preparePkcs12ForSigning(p12.path, req.workDir, p12Password);
    const rawProvisioningProfile = await decodeProvisioningProfile(profile.path);
    const provisioningProfileInfo = assertProvisioningProfileUsable(classifyProvisioningProfile(rawProvisioningProfile));
    const targetDeviceCheck = assertTargetDeviceAllowed(provisioningProfileInfo, targetUdid);
    const expectedBundleIdentifier = bundleId || sourceMetadata.bundleIdentifier;
    // Validate the selected IPA/Bundle ID against the profile before quota is
    // consumed and before ZSign is invoked. Do not silently rewrite a fixed App ID.
    assertBundleIdentifierAllowed(provisioningProfileInfo.applicationIdentifier, expectedBundleIdentifier);
    await consumeDailyQuota(req.user.uid);
    const outputPath = path.join(req.workDir, "signed-output.ipa");
    const args = ["-f", "-k", signingP12Path];
    if (p12Password) args.push("-p", p12Password);
    args.push("-m", profile.path);
    if (bundleId) args.push("-b", bundleId);
    if (appName) args.push("-n", appName);
    args.push("-o", outputPath, "-z", "6", ipa.path);
    try {
      await runZSign(args);
    } catch (error) {
      auditCode = error?.code || "SIGNING_FAILED";
      const raw = error instanceof Error ? error.message : "";
      if (p12Password && raw.includes(p12Password)) error.message = raw.split(p12Password).join("[REDACTED]");
      throw error;
    }

    const stat = await fs.stat(outputPath);
    if (!stat.isFile() || stat.size < 4) throw new Error("ZSign không tạo được tệp IPA đầu ra.");
    await assertIpaStructure(outputPath);
    const signedMetadata = await readIpaAppMetadata(outputPath);
    assertSignedBundleIdentifier(expectedBundleIdentifier, signedMetadata.bundleIdentifier);
    assertBundleIdentifierAllowed(provisioningProfileInfo.applicationIdentifier, signedMetadata.bundleIdentifier);
    const outputName = safeInputName(path.basename(ipa.originalname, path.extname(ipa.originalname)) + "-signed", "vang-store-signed", ".ipa");
    auditCode = "OK";
    await writeAudit(req.user.uid, "success", {
      ipaSize: ipa.size, p12Size: p12.size, profileSize: profile.size,
      bundleIdChanged: Boolean(bundleId), appNameChanged: Boolean(appName), durationMs: Date.now() - startedAt,
      requestId: req.requestId,
    });
    res.setHeader("X-Signing-Engine", "ZSign");
    res.setHeader("Cache-Control", "no-store, private");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.download(outputPath, outputName, async (error) => {
      if (error) console.error("Signed IPA delivery failed:", error.message);
      await fs.rm(req.workDir, { recursive: true, force: true }).catch(() => {});
    });
  } catch (error) {
    const message = friendlySigningError(error);
    auditCode = error?.code || "VALIDATION_OR_SIGNING_ERROR";
    await writeAudit(req.user.uid, "failed", {
      ipaSize: ipa?.size, p12Size: p12?.size, profileSize: profile?.size,
      bundleIdChanged: Boolean(String(req.body.bundleId || "").trim()),
      appNameChanged: Boolean(String(req.body.appName || "").trim()),
      durationMs: Date.now() - startedAt, errorCode: auditCode, requestId: req.requestId,
    });
    res.status(error?.message?.startsWith("Bạn đã đạt giới hạn") ? 429 : 400).json({
      error: message, code: auditCode, requestId: req.requestId,
      ...(error?.details ? { details: error.details } : {}),
    });
    await fs.rm(req.workDir, { recursive: true, force: true }).catch(() => {});
  }
});

const uploadChunkBytes = 3 * 1024 * 1024;
const uploadUuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function validateChunkUpload(fileIdValue, totalValue, uid, kind, maxBytes) {
  const fileId = String(fileIdValue || "");
  const totalChunks = Number(totalValue);
  const maxChunks = Math.ceil(maxBytes / uploadChunkBytes);
  if (!uploadUuidPattern.test(fileId)) throw new Error(`Mã phiên tải ${kind} không hợp lệ.`);
  if (!Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > maxChunks) {
    throw new Error(`Số phần tải ${kind} không hợp lệ hoặc vượt giới hạn.`);
  }
  const paths = Array.from({ length: totalChunks }, (_, index) =>
    `ipa-signing/${uid}/${kind}/${fileId}/chunk-${index}.part`,
  );
  return { fileId, totalChunks, paths };
}

async function downloadPrivateChunksToFile(pathnames, outputPath, maxBytes, label) {
  let totalBytes = 0;
  const source = Readable.from((async function* () {
    for (const pathname of pathnames) {
      const blob = await get(pathname, { access: "private", useCache: false });
      if (!blob || blob.statusCode !== 200 || !blob.stream) {
        const error = new Error(`Không tìm thấy một phần của ${label} trong kho lưu trữ tạm. Hãy tải tệp lên lại.`);
        error.code = "BLOB_NOT_FOUND";
        throw error;
      }
      if (Number.isFinite(blob.blob?.size) && blob.blob.size > uploadChunkBytes) {
        throw new Error(`Một phần của ${label} vượt giới hạn 3 MB.`);
      }
      for await (const chunk of Readable.fromWeb(blob.stream)) {
        totalBytes += chunk.length;
        if (totalBytes > maxBytes) throw new Error(`${label} vượt giới hạn ${Math.floor(maxBytes / 1024 / 1024)} MB.`);
        yield chunk;
      }
    }
  })());

  await pipeline(source, createWriteStream(outputPath, { flags: "wx", mode: 0o600 }));
  const stat = await fs.stat(outputPath);
  if (!stat.isFile() || stat.size <= 0 || stat.size !== totalBytes || stat.size > maxBytes) {
    await fs.rm(outputPath, { force: true }).catch(() => {});
    throw new Error(`${label} rỗng hoặc có dung lượng không hợp lệ.`);
  }
  return stat.size;
}

app.post("/v1/sign-blob", authenticate, enforceIpaSigningMaintenance, createWorkDir, async (req, res) => {
  const startedAt = Date.now();
  const body = req.body && typeof req.body === "object" ? req.body : {};
  let ipaPaths = [];
  let p12Paths = [];
  let profilePaths = [];
  let auditCode = "UNKNOWN";
  let ipaSize = 0;
  let p12Size = 0;
  let profileSize = 0;
  let outputBlobPath = null;
  let manifestBlobPath = null;
  const p12Password = String(body.p12Password || "");
  const bundleId = String(body.bundleId || "").trim();
  const appName = String(body.appName || "").trim();
  const targetUdid = String(body.targetUdid || "").trim().toUpperCase();

  try {
    if (!blobReady) throw new Error("Signing worker chưa cấu hình Vercel Blob. Hãy thêm BLOB_READ_WRITE_TOKEN và triển khai lại.");
    const ipaUpload = validateChunkUpload(body.ipaFileId, body.ipaTotalChunks, req.user.uid, "ipa", maxIpaBytes);
    const p12Upload = validateChunkUpload(body.p12FileId, body.p12TotalChunks, req.user.uid, "p12", maxCredentialFileBytes);
    const profileUpload = validateChunkUpload(body.profileFileId, body.profileTotalChunks, req.user.uid, "profile", maxProfileFileBytes);
    ipaPaths = ipaUpload.paths;
    p12Paths = p12Upload.paths;
    profilePaths = profileUpload.paths;
    if (!/\.(p12|pfx)$/i.test(String(body.p12FileName || ""))) throw new Error("Chứng chỉ phải là tệp .p12 hoặc .pfx.");
    if (!/\.mobileprovision$/i.test(String(body.profileFileName || ""))) throw new Error("Hồ sơ ký phải là tệp .mobileprovision.");
    if (bundleId && (bundleId.length > 180 || !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId))) {
      throw new Error("Bundle ID không đúng định dạng.");
    }
    if (appName.length > 100) throw new Error("Tên ứng dụng không được dài quá 100 ký tự.");
    if (targetUdid && !isSupportedUdid(targetUdid)) {
      const error = new Error("UDID phải có 40 ký tự hexadecimal hoặc 25 ký tự dạng 8-16.");
      error.code = "INVALID_TARGET_UDID";
      throw error;
    }

    const ipaPath = path.join(req.workDir, "input.ipa");
    const p12Path = path.join(req.workDir, "signing-cert.p12");
    const profilePath = path.join(req.workDir, "signing-profile.mobileprovision");
    ipaSize = await downloadPrivateChunksToFile(ipaPaths, ipaPath, maxIpaBytes, "IPA");
    p12Size = await downloadPrivateChunksToFile(p12Paths, p12Path, maxCredentialFileBytes, "P12/PFX");
    profileSize = await downloadPrivateChunksToFile(profilePaths, profilePath, maxProfileFileBytes, "Provisioning Profile");

    await assertIpaStructure(ipaPath);
    const signingP12Path = await preparePkcs12ForSigning(p12Path, req.workDir, p12Password);

    const rawProvisioningProfile = await decodeProvisioningProfile(profilePath);
    const provisioningProfileInfo = assertProvisioningProfileUsable(
      classifyProvisioningProfile(rawProvisioningProfile),
    );
    const targetDeviceCheck = assertTargetDeviceAllowed(provisioningProfileInfo, targetUdid);
    const sourceMetadata = await readIpaAppMetadata(ipaPath);
    const expectedBundleIdentifier = bundleId || sourceMetadata.bundleIdentifier;
    // Validate against the profile before consuming quota or running ZSign.
    // App ID Prefix may be a legacy prefix, not necessarily the Team ID.
    assertBundleIdentifierAllowed(provisioningProfileInfo.applicationIdentifier, expectedBundleIdentifier);
    // Consume quota only after the IPA, P12/PFX, provisioning profile, Bundle ID
    // and optional device check have all passed preflight validation.
    await consumeDailyQuota(req.user.uid);
    const outputPath = path.join(req.workDir, "signed-output.ipa");
    const args = ["-f", "-k", signingP12Path];
    if (p12Password) args.push("-p", p12Password);
    args.push("-m", profilePath);
    if (bundleId) args.push("-b", bundleId);
    if (appName) args.push("-n", appName);
    args.push("-o", outputPath, "-z", "6", ipaPath);

    try {
      await runZSign(args);
    } catch (error) {
      auditCode = error?.code || "SIGNING_FAILED";
      const raw = error instanceof Error ? error.message : "";
      if (p12Password && raw.includes(p12Password)) error.message = raw.split(p12Password).join("[REDACTED]");
      throw error;
    }

    const outputStat = await fs.stat(outputPath);
    if (!outputStat.isFile() || outputStat.size < 4) throw new Error("ZSign không tạo được tệp IPA đầu ra.");
    await assertIpaStructure(outputPath);

    const appMetadata = await readIpaAppMetadata(outputPath);
    assertSignedBundleIdentifier(expectedBundleIdentifier, appMetadata.bundleIdentifier);
    assertBundleIdentifierAllowed(provisioningProfileInfo.applicationIdentifier, appMetadata.bundleIdentifier);

    const sourceLabel = typeof body.originalName === "string" ? body.originalName : "vang-store";
    const outputName = safeInputName(path.basename(sourceLabel, path.extname(sourceLabel)) + "-signed", "vang-store-signed", ".ipa");
    const outputBlob = await put(`ipa-signing/${req.user.uid}/signed/${crypto.randomUUID()}-${outputName}`, createReadStream(outputPath), {
      access: "private",
      contentType: "application/octet-stream",
      addRandomSuffix: true,
      ttlDays: 1,
      multipart: outputStat.size > 10 * 1024 * 1024,
    });
    outputBlobPath = outputBlob.pathname;
    const validUntil = Date.now() + 60 * 60 * 1000;
    const signedToken = await issueSignedToken({ pathname: outputBlob.pathname, operations: ["get"], validUntil });
    const { presignedUrl } = await presignUrl(signedToken, {
      operation: "get",
      pathname: outputBlob.pathname,
      access: "private",
      validUntil,
    });

    let installUrl = null;
    let manifestUrl = null;
    if (provisioningProfileInfo.type === "ad-hoc" || provisioningProfileInfo.type === "enterprise") {
      const manifestXml = buildOtaManifestXml({
        ipaUrl: presignedUrl,
        bundleIdentifier: appMetadata.bundleIdentifier,
        bundleVersion: appMetadata.bundleVersion,
        title: appName || appMetadata.title,
      });
      const manifestBlob = await put(
        `ipa-signing/${req.user.uid}/manifests/${crypto.randomUUID()}.plist`,
        manifestXml,
        { access: "private", contentType: "application/xml; charset=utf-8", addRandomSuffix: true, ttlDays: 1 },
      );
      manifestBlobPath = manifestBlob.pathname;
      const manifestToken = await issueSignedToken({ pathname: manifestBlob.pathname, operations: ["get"], validUntil });
      const signedManifest = await presignUrl(manifestToken, {
        operation: "get",
        pathname: manifestBlob.pathname,
        access: "private",
        validUntil,
      });
      manifestUrl = signedManifest.presignedUrl;
      installUrl = buildItmsServicesUrl(manifestUrl);
    }

    const profileMessages = {
      "ad-hoc": "Đã ký bằng Ad Hoc Profile. Chỉ thiết bị có UDID nằm trong danh sách ProvisionedDevices của profile mới cài/chạy được. Mở liên kết bằng Safari trên thiết bị đã đăng ký.",
      enterprise: "Đã ký bằng In-House Profile. Chỉ sử dụng cho phân phối nội bộ tổ chức đủ điều kiện theo chương trình Apple Developer Enterprise.",
      development: "Đã ký bằng Development Profile. Chỉ thiết bị được liệt kê trong profile mới cài/chạy được; dùng quy trình phát triển phù hợp. Worker không tạo liên kết OTA phân phối công khai cho loại profile này.",
      "app-store": "Đã ký bằng App Store Distribution Profile. Profile này dùng cho quy trình App Store Connect; không thể cài trực tiếp qua liên kết OTA.",
      other: "Profile CMS hợp lệ đã được chấp nhận để ZSign thử ký. Phương thức cài đặt phụ thuộc loại profile và chính sách Apple; Worker không tự tạo OTA cho profile chưa nhận diện.",
    };
    const installation = {
      profileType: provisioningProfileInfo.type,
      registeredDeviceCount: provisioningProfileInfo.registeredDeviceCount,
      profileExpiresAt: provisioningProfileInfo.expiresAt,
      applicationIdentifier: provisioningProfileInfo.applicationIdentifier,
      bundleIdentifier: appMetadata.bundleIdentifier,
      appVersion: appMetadata.bundleVersion,
      requiresRegisteredDevice: provisioningProfileInfo.type === "ad-hoc" || provisioningProfileInfo.type === "development",
      targetDeviceProvided: targetDeviceCheck.provided,
      targetDeviceRegistered: targetDeviceCheck.registered,
      message: (profileMessages[provisioningProfileInfo.type] || profileMessages.other) + (targetDeviceCheck.registered === true ? " UDID vừa kiểm tra đã có trong danh sách thiết bị của profile." : ""),
    };

    auditCode = "OK";
    await writeAudit(req.user.uid, "success", {
      ipaSize, p12Size, profileSize, bundleIdChanged: Boolean(bundleId),
      appNameChanged: Boolean(appName), durationMs: Date.now() - startedAt,
      requestId: req.requestId,
      profileType: provisioningProfileInfo.type,
      registeredDeviceCount: provisioningProfileInfo.registeredDeviceCount,
    });
    return res.json({
      url: presignedUrl,
      name: outputName,
      expiresAt: new Date(validUntil).toISOString(),
      installUrl,
      manifestUrl,
      installation,
      requestId: req.requestId,
    });
  } catch (error) {
    auditCode = error?.code || "VALIDATION_OR_SIGNING_ERROR";
    const partialOutputs = [outputBlobPath, manifestBlobPath].filter(Boolean);
    if (partialOutputs.length && blobReady) {
      await del(partialOutputs).catch((cleanupError) => console.error("Could not delete partial signing outputs:", cleanupError instanceof Error ? cleanupError.message : "unknown"));
    }
    const message = friendlySigningError(error);
    await writeAudit(req.user.uid, "failed", {
      ipaSize, p12Size, profileSize, bundleIdChanged: Boolean(bundleId),
      appNameChanged: Boolean(appName), durationMs: Date.now() - startedAt, errorCode: auditCode, requestId: req.requestId,
    });
    const status = error?.code === "SIGNING_TIMEOUT" ? 504
      : message.startsWith("Bạn đã đạt giới hạn") ? 429
      : error?.code === "BLOB_NOT_FOUND" ? 404
      : 400;
    return res.status(status).json({
      error: message, code: auditCode, requestId: req.requestId,
      ...(error?.details ? { details: error.details } : {}),
    });
  } finally {
    const toDelete = [...ipaPaths, ...p12Paths, ...profilePaths];
    if (toDelete.length && blobReady) await del(toDelete).catch((error) => console.error("Could not delete private input chunks:", error instanceof Error ? error.message : "unknown"));
    if (req.workDir) await fs.rm(req.workDir, { recursive: true, force: true }).catch(() => {});
  }
});

app.use(async (error, req, res, _next) => {
  if (req.workDir) await fs.rm(req.workDir, { recursive: true, force: true }).catch(() => {});

  const requestId = req.requestId || crypto.randomUUID();
  const isBodyTooLarge = error?.type === "entity.too.large" || error?.status === 413 || error?.statusCode === 413;
  const isInvalidJson = error instanceof SyntaxError && Object.prototype.hasOwnProperty.call(error, "body");

  if (error instanceof multer.MulterError) {
    const message = error.code === "LIMIT_FILE_SIZE" ? "Tệp tải lên vượt giới hạn dung lượng." : "Tệp tải lên không đúng định dạng hoặc vượt số lượng cho phép.";
    return res.status(400).json({ error: message, requestId });
  }

  let status = 500;
  let publicMessage = "Signing worker gặp lỗi nội bộ. Vui lòng thử lại sau.";
  if (isBodyTooLarge) {
    status = 413;
    publicMessage = "Thông tin yêu cầu ký vượt giới hạn cho phép. Hãy tải lại trang và thử lại.";
  } else if (isInvalidJson) {
    status = 400;
    publicMessage = "Dữ liệu yêu cầu ký không phải JSON hợp lệ.";
  } else if (error?.code === "WORKDIR_UNAVAILABLE") {
    status = 503;
    publicMessage = "Worker chưa tạo được vùng xử lý tạm thời. Quản trị viên cần kiểm tra cấu hình thư mục tạm của Container.";
  }

  // Include request path and safe error metadata only. Do not log request bodies,
  // Firebase tokens, Blob tokens, P12 passwords, or Authorization headers.
  console.error("Signing worker request error:", JSON.stringify({
    requestId,
    method: req.method,
    path: req.path,
    status,
    code: error?.code || error?.type || null,
    message: error instanceof Error ? error.message : "unknown",
    causeCode: error?.cause?.code || null,
    causeMessage: error?.cause instanceof Error ? error.cause.message : null,
  }));

  res.setHeader("X-Request-ID", requestId);
  return res.status(status).json({
    error: `${publicMessage} Mã yêu cầu: ${requestId}.`,
    requestId,
    code: error?.code || error?.type || (status === 500 ? "INTERNAL_ERROR" : null),
  });
});

const server = app.listen(port, "0.0.0.0", () => {
  console.log(`VANG IPA signing worker listening on ${port}; Firebase ${firebaseReady ? "ready" : "not configured"}; ZSign ${zsignReady ? "ready" : "not ready"}; OpenSSL ${opensslReady ? "ready" : "not ready"}; Blob ${blobReady ? "ready" : "not configured"}; CORS origins ${allowedOrigins.size}.`);
});
server.requestTimeout = 270_000;
server.headersTimeout = 60 * 1000;

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
