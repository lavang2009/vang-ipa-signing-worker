import crypto from "node:crypto";

export function classifyProvisioningProfile(profile) {
  const provisionedDevices = Array.isArray(profile?.ProvisionedDevices)
    ? profile.ProvisionedDevices.filter((item) => typeof item === "string" && item.trim())
    : [];
  const provisionsAllDevices = profile?.ProvisionsAllDevices === true;
  const getTaskAllow = profile?.Entitlements?.["get-task-allow"];

  // Support every common iOS provisioning profile category for signing.
  // Installation distribution remains type-specific: App Store profiles are
  // not OTA-installable, while Ad Hoc/In-House can produce an OTA manifest.
  let type = "other";
  if (provisionsAllDevices) type = "enterprise";
  else if (provisionedDevices.length > 0 && getTaskAllow === false) type = "ad-hoc";
  else if (provisionedDevices.length > 0 && getTaskAllow === true) type = "development";
  else if (getTaskAllow === false) type = "app-store";

  const rawExpiration = profile?.ExpirationDate;
  const expirationDate = rawExpiration instanceof Date
    ? rawExpiration
    : rawExpiration
      ? new Date(rawExpiration)
      : null;

  const applicationIdentifier = typeof (profile?.Entitlements?.["application-identifier"] || profile?.Entitlements?.["com.apple.application-identifier"]) === "string"
    ? (profile.Entitlements["application-identifier"] || profile.Entitlements["com.apple.application-identifier"])
    : "";
  const appIdSeparator = applicationIdentifier.indexOf(".");

  return {
    type,
    registeredDeviceCount: provisionedDevices.length,
    provisionedDevices,
    expiresAt: expirationDate && Number.isFinite(expirationDate.getTime())
      ? expirationDate.toISOString()
      : null,
    applicationIdentifier,
    appIdPrefix: appIdSeparator > 0 ? applicationIdentifier.slice(0, appIdSeparator) : "",
    profileBundlePattern: appIdSeparator > 0 ? applicationIdentifier.slice(appIdSeparator + 1) : "",
    profileName: typeof profile?.Name === "string" ? profile.Name : "",
    profileUuid: typeof profile?.UUID === "string" ? profile.UUID : "",
    teamIdentifiers: Array.isArray(profile?.TeamIdentifier)
      ? profile.TeamIdentifier.filter((item) => typeof item === "string" && item.trim())
      : [],
  };
}

export function assertProvisioningProfileUsable(profileInfo, now = Date.now()) {
  if (!profileInfo || !["ad-hoc", "enterprise", "development", "app-store", "other"].includes(profileInfo.type)) {
    throw new Error("Provisioning Profile không thuộc định dạng iOS được hỗ trợ.");
  }
  if (!profileInfo.expiresAt) {
    throw new Error("Provisioning Profile không có ngày hết hạn hợp lệ.");
  }
  if (new Date(profileInfo.expiresAt).getTime() <= now) {
    throw new Error("Provisioning Profile đã hết hạn. Hãy tạo và tải profile mới từ Apple Developer.");
  }
  if (!profileInfo.applicationIdentifier || !profileInfo.applicationIdentifier.includes(".")) {
    throw new Error("Provisioning Profile thiếu application-identifier hợp lệ.");
  }
  return profileInfo;
}


export function isSupportedUdid(value) {
  return typeof value === "string" && (
    /^[A-Fa-f0-9]{40}$/.test(value) ||
    /^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{16}$/.test(value)
  );
}

/** Validate an optional target device against the registered device list in a signed profile. */
export function assertTargetDeviceAllowed(profileInfo, targetUdid) {
  const normalized = typeof targetUdid === "string" ? targetUdid.trim().toUpperCase() : "";
  if (!normalized) return { provided: false, registered: null };
  if (!isSupportedUdid(normalized)) {
    const error = new Error("UDID phải có 40 ký tự hexadecimal hoặc 25 ký tự dạng 8-16.");
    error.code = "INVALID_TARGET_UDID";
    throw error;
  }
  if (profileInfo?.type === "ad-hoc" || profileInfo?.type === "development") {
    const devices = Array.isArray(profileInfo.provisionedDevices) ? profileInfo.provisionedDevices : [];
    const registered = devices.some((device) => typeof device === "string" && device.trim().toUpperCase() === normalized);
    if (!registered) {
      const error = new Error("UDID bạn nhập chưa nằm trong danh sách thiết bị của Provisioning Profile. Hãy đăng ký thiết bị trong Apple Developer, tạo và tải lại profile rồi ký lại.");
      error.code = "TARGET_DEVICE_NOT_REGISTERED";
      throw error;
    }
    return { provided: true, registered: true };
  }
  return { provided: true, registered: null };
}

const BUNDLE_IDENTIFIER_PATTERN = /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/;

/**
 * Match the bundle identifier against the App ID in a provisioning profile.
 * Apple defines application-identifier as <App ID Prefix>.<Bundle ID>.
 * The prefix is NOT always the Team ID, so deliberately compare only the
 * profile's suffix after its first dot. Wildcards are supported only as the
 * complete App ID (`*`) or as the final component (`com.example.*`).
 */
export function isBundleIdentifierAllowed(applicationIdentifier, bundleIdentifier) {
  if (typeof applicationIdentifier !== "string" || !applicationIdentifier.trim()) return false;
  if (typeof bundleIdentifier !== "string" || !bundleIdentifier.trim()) return false;

  const appId = applicationIdentifier.trim();
  const bundleId = bundleIdentifier.trim();
  if (!BUNDLE_IDENTIFIER_PATTERN.test(bundleId)) return false;

  const separator = appId.indexOf(".");
  if (separator < 1 || separator === appId.length - 1) return false;

  const appIdPrefix = appId.slice(0, separator);
  const profilePattern = appId.slice(separator + 1);
  if (!appIdPrefix || appIdPrefix.includes("*") || !profilePattern) return false;

  if (profilePattern === "*") return true;
  if (profilePattern === bundleId) return true;

  // Apple wildcard App IDs must have a single trailing wildcard. Require at
  // least one complete bundle-ID component after the fixed prefix.
  if (profilePattern.endsWith(".*") && !profilePattern.slice(0, -1).includes("*")) {
    const fixedPrefix = profilePattern.slice(0, -1); // includes final dot
    return bundleId.startsWith(fixedPrefix) && bundleId.length > fixedPrefix.length;
  }
  return false;
}

/** Fail early, before consuming quota or invoking ZSign, with safe diagnostics. */
export function getApplicationIdentifierParts(applicationIdentifier) {
  if (typeof applicationIdentifier !== "string") return null;
  const value = applicationIdentifier.trim();
  const separator = value.indexOf(".");
  if (separator < 1 || separator === value.length - 1) return null;
  const appIdPrefix = value.slice(0, separator);
  const profileBundlePattern = value.slice(separator + 1);
  if (!/^[A-Za-z0-9-]+$/.test(appIdPrefix) || !profileBundlePattern) return null;
  return { appIdPrefix, profileBundlePattern };
}

/** Preserve the IPA's embedded CFBundleIdentifier. This signing workflow must
 * never silently rewrite it to make an unrelated profile appear compatible. */
export function assertOriginalBundleIdentifier(sourceBundleIdentifier, requestedBundleIdentifier = "") {
  const source = typeof sourceBundleIdentifier === "string" ? sourceBundleIdentifier.trim() : "";
  const requested = typeof requestedBundleIdentifier === "string" ? requestedBundleIdentifier.trim() : "";
  if (!source || !BUNDLE_IDENTIFIER_PATTERN.test(source)) {
    const error = new Error("Không đọc được Bundle ID gốc hợp lệ từ IPA.");
    error.code = "INVALID_SOURCE_BUNDLE_ID";
    throw error;
  }
  if (requested && requested !== source) {
    const error = new Error(
      `VANG STORE đang giữ nguyên Bundle ID gốc của IPA (${source}) và không cho phép đổi sang ${requested}. Hãy dùng IPA có Bundle ID đúng hoặc tải Provisioning Profile tương ứng với Bundle ID gốc.`,
    );
    error.code = "BUNDLE_ID_OVERRIDE_DISABLED";
    error.details = {
      sourceBundleIdentifier: source,
      requestedBundleIdentifier: requested,
      policy: "PRESERVE_SOURCE_BUNDLE_ID",
    };
    throw error;
  }
  return source;
}

export function assertBundleIdentifierAllowed(applicationIdentifier, bundleIdentifier, profileInfo = {}) {
  if (isBundleIdentifierAllowed(applicationIdentifier, bundleIdentifier)) return true;

  const parts = getApplicationIdentifierParts(applicationIdentifier);
  const bundlePattern = parts?.profileBundlePattern || "(không đọc được)";
  const prefix = parts?.appIdPrefix || "(không đọc được)";
  const error = new Error(
    `Provisioning Profile không cấp quyền cho Bundle ID gốc của IPA. IPA: "${String(bundleIdentifier || "(trống)")}"; App ID trong profile: "${String(applicationIdentifier || "(thiếu)")}". Hãy giữ nguyên Bundle ID và tải profile được tạo cho đúng App ID này từ Apple Developer. Worker không tự đổi Bundle ID hoặc bỏ qua entitlement.`,
  );
  error.code = "BUNDLE_ID_PROFILE_MISMATCH";
  error.details = {
    bundleIdentifier: typeof bundleIdentifier === "string" ? bundleIdentifier : null,
    sourceBundleIdentifier: typeof bundleIdentifier === "string" ? bundleIdentifier : null,
    applicationIdentifier: typeof applicationIdentifier === "string" ? applicationIdentifier : null,
    appIdPrefix: parts?.appIdPrefix || null,
    profileBundlePattern: parts?.profileBundlePattern || null,
    profileName: profileInfo.profileName || null,
    profileUuid: profileInfo.profileUuid || null,
    teamIdentifiers: Array.isArray(profileInfo.teamIdentifiers) ? profileInfo.teamIdentifiers : [],
    policy: "PRESERVE_SOURCE_BUNDLE_ID",
    nextAction: "DOWNLOAD_MATCHING_PROVISIONING_PROFILE_FROM_APPLE_DEVELOPER",
  };
  throw error;
}


function toCertificateBytes(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  return null;
}

/** Ensure the signing certificate's DER bytes are one of the certificates
 * explicitly authorized by the Apple-signed profile. Fingerprints are SHA-256
 * hex strings from X509 DER, never the private key. */
export function assertSigningCertificateInProfile(profile, signingCertificateFingerprints = []) {
  const allowedCertificates = Array.isArray(profile?.DeveloperCertificates)
    ? profile.DeveloperCertificates.map(toCertificateBytes).filter(Boolean)
    : [];
  const allowedFingerprints = new Set(allowedCertificates.map((bytes) =>
    crypto.createHash("sha256").update(bytes).digest("hex").toLowerCase(),
  ));
  const supplied = new Set(signingCertificateFingerprints
    .filter((value) => typeof value === "string")
    .map((value) => value.replace(/[^a-f0-9]/gi, "").toLowerCase())
    .filter(Boolean));

  if (!allowedFingerprints.size || !supplied.size || ![...supplied].some((value) => allowedFingerprints.has(value))) {
    const error = new Error(
      "Chứng chỉ trong P12/PFX không nằm trong DeveloperCertificates của Provisioning Profile. Hãy chọn đúng cặp P12 và profile được tạo cùng chứng chỉ trên Apple Developer.",
    );
    error.code = "SIGNING_CERTIFICATE_NOT_IN_PROFILE";
    error.details = {
      profileCertificateCount: allowedFingerprints.size,
      providedCertificateCount: supplied.size,
      matchingCertificate: false,
    };
    throw error;
  }
  return true;
}

function escapeXml(value) {
  return String(value ?? "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export function buildOtaManifestXml({ ipaUrl, bundleIdentifier, bundleVersion, title }) {
  const parsedUrl = new URL(ipaUrl);
  if (parsedUrl.protocol !== "https:") throw new Error("IPA installation URL must use HTTPS.");
  if (!bundleIdentifier || !bundleVersion || !title) {
    throw new Error("Thiếu Bundle ID, phiên bản hoặc tên ứng dụng để tạo manifest iOS.");
  }

  return `<?xml version="1.0" encoding="UTF-8"?>\n` +
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n` +
    `<plist version="1.0"><dict><key>items</key><array><dict>` +
    `<key>assets</key><array><dict><key>kind</key><string>software-package</string>` +
    `<key>url</key><string>${escapeXml(ipaUrl)}</string></dict></array>` +
    `<key>metadata</key><dict>` +
    `<key>bundle-identifier</key><string>${escapeXml(bundleIdentifier)}</string>` +
    `<key>bundle-version</key><string>${escapeXml(bundleVersion)}</string>` +
    `<key>kind</key><string>software</string>` +
    `<key>title</key><string>${escapeXml(title)}</string>` +
    `</dict></dict></array></dict></plist>`;
}

export function buildItmsServicesUrl(manifestUrl) {
  const parsedUrl = new URL(manifestUrl);
  if (parsedUrl.protocol !== "https:") throw new Error("Manifest installation URL must use HTTPS.");
  return `itms-services://?action=download-manifest&url=${encodeURIComponent(parsedUrl.toString())}`;
}
