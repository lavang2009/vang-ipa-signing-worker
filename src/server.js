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
import { validateCertificateArchiveEntries } from "./archive-validation.js";
import { applyCors, parseAllowedOrigins } from "./cors.js";
import { del, get, issueSignedToken, presignUrl, put } from "@vercel/blob";

const execFileAsync = promisify(execFile);
const app = express();
const port = Number(process.env.PORT || 8080);
const maxIpaBytes = Number(process.env.SIGNING_MAX_IPA_BYTES || 512 * 1024 * 1024);
const maxCertZipBytes = Number(process.env.SIGNING_MAX_CERT_ZIP_BYTES || 20 * 1024 * 1024);
const dailyLimit = Number(process.env.SIGNING_DAILY_LIMIT || 10);
const signingTimeout = Number(process.env.SIGNING_TIMEOUT_MS || 240_000);
const zsignBin = process.env.ZSIGN_BIN || "/usr/local/bin/zsign";
const blobReady = Boolean(process.env.BLOB_READ_WRITE_TOKEN);
const workerBuild = "ipa-sign-blob-cors-diagnostics-2026-11-13";

// Keep the CORS allow-list strict and independently unit-tested.
const allowedOrigins = parseAllowedOrigins(process.env.ALLOWED_ORIGINS || "");

function initFirebase() {
  if (getApps().length) return getApps()[0];
  let account = null;
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    account = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
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
try { initFirebase(); firebaseReady = true; }
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

app.use((req, res, next) => {
  // Server-to-server requests without an Origin remain supported. Browser requests
  // must match the exact allow-list and receive the headers required for Bearer auth.
  if (!applyCors(req, res, allowedOrigins)) {
    return res.status(403).json({ error: "Origin này không được phép sử dụng signing worker." });
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
    status: firebaseReady && zsignReady && blobReady ? "ready" : "not_ready",
    health: "/healthz",
    signingEndpoint: "POST /v1/sign-blob",
    engine: zsignReady ? "zsign" : "unavailable",
  });
});

app.get("/healthz", (_req, res) => {
  const ready = firebaseReady && zsignReady && blobReady;
  res.setHeader("Cache-Control", "no-store, max-age=0");
  res.status(ready ? 200 : 503).json({
    ok: ready,
    service: "VANG STORE IPA Signing Worker",
    build: workerBuild,
    engine: zsignReady ? "zsign" : "unavailable",
    firebase: firebaseReady,
    zsign: zsignReady,
    blob: blobReady,
    signBlob: true,
    corsConfigured: allowedOrigins.size > 0,
    allowedOriginCount: allowedOrigins.size,
    signingEndpoint: "POST /v1/sign-blob",
    ...(zsignReady ? { zsignVersion } : { zsignError }),
  });
});

async function authenticate(req, res, next) {
  try {
    if (!firebaseReady) return res.status(503).json({ error: "Signing worker chưa cấu hình Firebase Admin." });
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer\s+(.+)$/i);
    if (!match) return res.status(401).json({ error: "Bạn cần đăng nhập để sử dụng công cụ ký IPA." });
    req.user = await getAuth().verifyIdToken(match[1], true);
    next();
  } catch {
    res.status(401).json({ error: "Phiên đăng nhập không hợp lệ hoặc đã hết hạn. Hãy đăng nhập lại." });
  }
}

async function createWorkDir(req, _res, next) {
  try {
    req.workDir = await fs.mkdtemp(path.join(os.tmpdir(), "vang-sign-"));
    next();
  } catch {
    next(new Error("Không thể tạo vùng làm việc tạm thời."));
  }
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, _file, callback) => callback(null, req.workDir),
    filename: (_req, file, callback) => callback(null, `${crypto.randomUUID()}${path.extname(file.originalname).toLowerCase()}`),
  }),
  limits: { files: 2, fields: 6, fileSize: maxIpaBytes, fieldSize: 4096 },
});

function safeInputName(value, fallback, extension) {
  const base = path.basename(String(value || fallback)).replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 90);
  return base.toLowerCase().endsWith(extension) ? base : `${base}${extension}`;
}

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

async function extractZipEntry(zipPath, entryName, outputPath, maxBytes, label) {
  let stdout;
  try {
    const result = await execFileAsync("unzip", ["-p", zipPath, entryName], { encoding: "buffer", maxBuffer: maxBytes + 1, timeout: 30_000 });
    stdout = result.stdout;
  } catch {
    throw new Error(`Không giải nén được ${label} từ ZIP hoặc tệp vượt giới hạn dung lượng.`);
  }
  if (!stdout || stdout.length === 0 || stdout.length > maxBytes) throw new Error(`${label} rỗng hoặc vượt giới hạn dung lượng.`);
  await fs.writeFile(outputPath, stdout, { flag: "wx", mode: 0o600 });
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
      certificateZipSize: Number(details.certificateZipSize || 0),
      bundleIdChanged: Boolean(details.bundleIdChanged),
      appNameChanged: Boolean(details.appNameChanged),
      durationMs: Number(details.durationMs || 0),
      errorCode: details.errorCode || null,
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
    if (/mac verify error|password|pkcs12|bad decrypt|unable to load private key/.test(lower)) return "Không đọc được P12. Kiểm tra file chứng chỉ và mật khẩu P12 (nếu tệp có mật khẩu).";
    if (/provision|profile|entitlement|bundle identifier|application-identifier/.test(lower)) return "Provisioning profile không tương thích với chứng chỉ, Bundle ID hoặc quyền của ứng dụng.";
    return "ZSign không thể ký IPA này. Hãy kiểm tra chứng chỉ còn hạn, profile phù hợp và thử lại bằng bộ tệp hợp lệ.";
  }
  if (error?.code === "ENOENT") return "Signing worker thiếu chương trình unzip hoặc ZSign. Hãy liên hệ quản trị viên.";
  return raw || "Không thể xử lý tệp ký IPA.";
}

app.post("/v1/sign", authenticate, createWorkDir, upload.fields([{ name: "ipa", maxCount: 1 }, { name: "certificateZip", maxCount: 1 }]), async (req, res, next) => {
  const startedAt = Date.now();
  let auditStatus = "failed";
  let auditCode = "UNKNOWN";
  const files = req.files || {};
  const ipa = files.ipa?.[0];
  const certificateZip = files.certificateZip?.[0];
  try {
    if (!ipa || !certificateZip) throw new Error("Vui lòng tải lên cả file IPA và ZIP chứng chỉ.");
    if (!ipa.originalname.toLowerCase().endsWith(".ipa")) throw new Error("File ứng dụng phải có đuôi .ipa.");
    if (!certificateZip.originalname.toLowerCase().endsWith(".zip")) throw new Error("Gói chứng chỉ phải là file .zip.");
    if (ipa.size > maxIpaBytes) throw new Error(`IPA vượt giới hạn ${Math.floor(maxIpaBytes / 1024 / 1024)} MB.`);
    if (certificateZip.size > maxCertZipBytes) throw new Error(`ZIP chứng chỉ vượt giới hạn ${Math.floor(maxCertZipBytes / 1024 / 1024)} MB.`);
    const p12Password = String(req.body.p12Password || "");
    const bundleId = String(req.body.bundleId || "").trim();
    const appName = String(req.body.appName || "").trim();
    if (bundleId && (bundleId.length > 180 || !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId))) throw new Error("Bundle ID không đúng định dạng.");
    if (appName.length > 100) throw new Error("Tên ứng dụng không được dài quá 100 ký tự.");

    await assertIpaStructure(ipa.path);
    await ensureZipMagic(certificateZip.path, "ZIP chứng chỉ");
    const zipEntries = await getZipEntries(certificateZip.path);
    const certEntries = validateCertificateArchiveEntries(zipEntries);
    const p12Path = path.join(req.workDir, "signing-cert.p12");
    const profilePath = path.join(req.workDir, "signing-profile.mobileprovision");
    await extractZipEntry(certificateZip.path, certEntries.p12Entry, p12Path, 10 * 1024 * 1024, "P12/PFX");
    await extractZipEntry(certificateZip.path, certEntries.profileEntry, profilePath, 10 * 1024 * 1024, "MobileProvision");

    // Charge quota only after both uploads and the certificate archive have passed validation.
    await consumeDailyQuota(req.user.uid);
    const outputPath = path.join(req.workDir, "signed-output.ipa");
    const args = ["-f", "-k", p12Path];
    if (p12Password) args.push("-p", p12Password);
    args.push("-m", profilePath);
    if (bundleId) args.push("-b", bundleId);
    if (appName) args.push("-n", appName);
    args.push("-o", outputPath, "-z", "6", ipa.path);

    try {
      await runZSign(args);
    } catch (error) {
      auditCode = error?.code || "SIGNING_FAILED";
      const raw = error instanceof Error ? error.message : "";
      // Never forward or persist the P12 password, even if a native tool echoes arguments.
      if (p12Password && raw.includes(p12Password)) error.message = raw.split(p12Password).join("[REDACTED]");
      throw error;
    }

    const stat = await fs.stat(outputPath);
    if (!stat.isFile() || stat.size < 4) throw new Error("ZSign không tạo được tệp IPA đầu ra.");
    await assertIpaStructure(outputPath);
    auditStatus = "success";
    auditCode = "OK";
    await writeAudit(req.user.uid, auditStatus, {
      ipaSize: ipa.size, certificateZipSize: certificateZip.size,
      bundleIdChanged: Boolean(bundleId), appNameChanged: Boolean(appName), durationMs: Date.now() - startedAt,
    });

    const outputName = safeInputName(path.basename(ipa.originalname, path.extname(ipa.originalname)) + "-signed", "vang-store-signed", ".ipa");
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
      ipaSize: ipa?.size, certificateZipSize: certificateZip?.size,
      bundleIdChanged: Boolean(String(req.body.bundleId || "").trim()),
      appNameChanged: Boolean(String(req.body.appName || "").trim()),
      durationMs: Date.now() - startedAt, errorCode: auditCode,
    });
    res.status(error?.message?.startsWith("Bạn đã đạt giới hạn") ? 429 : 400).json({ error: message });
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

app.post("/v1/sign-blob", authenticate, createWorkDir, async (req, res) => {
  const startedAt = Date.now();
  const body = req.body && typeof req.body === "object" ? req.body : {};
  let ipaPaths = [];
  let certificatePaths = [];
  let auditCode = "UNKNOWN";
  let ipaSize = 0;
  let certificateZipSize = 0;
  const p12Password = String(body.p12Password || "");
  const bundleId = String(body.bundleId || "").trim();
  const appName = String(body.appName || "").trim();

  try {
    if (!blobReady) throw new Error("Signing worker chưa cấu hình Vercel Blob. Hãy thêm BLOB_READ_WRITE_TOKEN và triển khai lại.");
    const ipaUpload = validateChunkUpload(body.ipaFileId, body.ipaTotalChunks, req.user.uid, "ipa", maxIpaBytes);
    const certificateUpload = validateChunkUpload(body.certificateFileId, body.certificateTotalChunks, req.user.uid, "certificate", maxCertZipBytes);
    ipaPaths = ipaUpload.paths;
    certificatePaths = certificateUpload.paths;
    if (bundleId && (bundleId.length > 180 || !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId))) {
      throw new Error("Bundle ID không đúng định dạng.");
    }
    if (appName.length > 100) throw new Error("Tên ứng dụng không được dài quá 100 ký tự.");

    const ipaPath = path.join(req.workDir, "input.ipa");
    const certificateZipPath = path.join(req.workDir, "certificate.zip");
    ipaSize = await downloadPrivateChunksToFile(ipaPaths, ipaPath, maxIpaBytes, "IPA");
    certificateZipSize = await downloadPrivateChunksToFile(certificatePaths, certificateZipPath, maxCertZipBytes, "ZIP chứng chỉ");

    await assertIpaStructure(ipaPath);
    await ensureZipMagic(certificateZipPath, "ZIP chứng chỉ");
    const zipEntries = await getZipEntries(certificateZipPath);
    const certEntries = validateCertificateArchiveEntries(zipEntries);
    const p12Path = path.join(req.workDir, "signing-cert.p12");
    const profilePath = path.join(req.workDir, "signing-profile.mobileprovision");
    await extractZipEntry(certificateZipPath, certEntries.p12Entry, p12Path, 10 * 1024 * 1024, "P12/PFX");
    await extractZipEntry(certificateZipPath, certEntries.profileEntry, profilePath, 10 * 1024 * 1024, "MobileProvision");

    // Consume quota only after all private chunks and the credential archive are validated.
    await consumeDailyQuota(req.user.uid);
    const outputPath = path.join(req.workDir, "signed-output.ipa");
    const args = ["-f", "-k", p12Path];
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

    const sourceLabel = typeof body.originalName === "string" ? body.originalName : "vang-store";
    const outputName = safeInputName(path.basename(sourceLabel, path.extname(sourceLabel)) + "-signed", "vang-store-signed", ".ipa");
    const outputBlob = await put(`ipa-signing/${req.user.uid}/signed/${crypto.randomUUID()}-${outputName}`, createReadStream(outputPath), {
      access: "private",
      contentType: "application/octet-stream",
      addRandomSuffix: true,
      ttlDays: 1,
      multipart: outputStat.size > 10 * 1024 * 1024,
    });
    const validUntil = Date.now() + 20 * 60 * 1000;
    const signedToken = await issueSignedToken({ pathname: outputBlob.pathname, operations: ["get"], validUntil });
    const { presignedUrl } = await presignUrl(signedToken, {
      operation: "get",
      pathname: outputBlob.pathname,
      access: "private",
      validUntil,
    });

    auditCode = "OK";
    await writeAudit(req.user.uid, "success", {
      ipaSize, certificateZipSize, bundleIdChanged: Boolean(bundleId),
      appNameChanged: Boolean(appName), durationMs: Date.now() - startedAt,
    });
    return res.json({ url: presignedUrl, name: outputName, expiresAt: new Date(validUntil).toISOString() });
  } catch (error) {
    auditCode = error?.code || "VALIDATION_OR_SIGNING_ERROR";
    const message = friendlySigningError(error);
    await writeAudit(req.user.uid, "failed", {
      ipaSize, certificateZipSize, bundleIdChanged: Boolean(bundleId),
      appNameChanged: Boolean(appName), durationMs: Date.now() - startedAt, errorCode: auditCode,
    });
    const status = error?.code === "SIGNING_TIMEOUT" ? 504
      : message.startsWith("Bạn đã đạt giới hạn") ? 429
      : error?.code === "BLOB_NOT_FOUND" ? 404
      : 400;
    return res.status(status).json({ error: message });
  } finally {
    const toDelete = [...ipaPaths, ...certificatePaths];
    if (toDelete.length && blobReady) await del(toDelete).catch((error) => console.error("Could not delete private input chunks:", error instanceof Error ? error.message : "unknown"));
    if (req.workDir) await fs.rm(req.workDir, { recursive: true, force: true }).catch(() => {});
  }
});

app.use(async (error, req, res, _next) => {
  if (req.workDir) await fs.rm(req.workDir, { recursive: true, force: true }).catch(() => {});
  if (error instanceof multer.MulterError) {
    const message = error.code === "LIMIT_FILE_SIZE" ? "Tệp tải lên vượt giới hạn dung lượng." : "Tệp tải lên không đúng định dạng hoặc vượt số lượng cho phép.";
    return res.status(400).json({ error: message });
  }
  console.error("Signing worker request error:", error instanceof Error ? error.message : "unknown");
  return res.status(500).json({ error: "Signing worker gặp lỗi nội bộ. Vui lòng thử lại sau." });
});

const server = app.listen(port, "0.0.0.0", () => {
  console.log(`VANG IPA signing worker listening on ${port}; Firebase ${firebaseReady ? "ready" : "not configured"}; ZSign ${zsignReady ? "ready" : "not ready"}; Blob ${blobReady ? "ready" : "not configured"}; CORS origins ${allowedOrigins.size}.`);
  if (allowedOrigins.size === 0) console.error("ALLOWED_ORIGINS is empty. Browser signing requests will be rejected by CORS.");
});
server.requestTimeout = 270_000;
server.headersTimeout = 60 * 1000;

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
