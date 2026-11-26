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

  const entitlements = profile?.Entitlements && typeof profile.Entitlements === "object"
    ? profile.Entitlements
    : {};
  // iOS normally uses application-identifier. Mac Catalyst profiles can
  // carry com.apple.application-identifier as well; validate every supplied
  // value rather than silently preferring one if the two disagree.
  const applicationIdentifiers = [...new Set([
    entitlements["application-identifier"],
    entitlements["com.apple.application-identifier"],
  ].filter((value) => typeof value === "string" && value.trim()).map((value) => value.trim()))];
  const applicationIdentifier = applicationIdentifiers[0] || "";
  const appIdSeparator = applicationIdentifier.indexOf(".");
  const profileBundlePattern = appIdSeparator > 0 ? applicationIdentifier.slice(appIdSeparator + 1) : "";
  const appIdTypes = [...new Set(applicationIdentifiers.map((value) =>
    parseProfileApplicationIdentifier(value)?.appIdType || "unknown",
  ))];
  const appIdType = appIdTypes.length === 1 ? appIdTypes[0] : appIdTypes.length ? "mixed" : "unknown";
  const hasWildcardAppId = applicationIdentifiers.some((value) =>
    parseProfileApplicationIdentifier(value)?.appIdType === "wildcard",
  );

  return {
    type,
    registeredDeviceCount: provisionedDevices.length,
    provisionedDevices,
    expiresAt: expirationDate && Number.isFinite(expirationDate.getTime())
      ? expirationDate.toISOString()
      : null,
    applicationIdentifier,
    applicationIdentifiers,
    appIdType,
    hasWildcardAppId,
    appIdPrefix: appIdSeparator > 0 ? applicationIdentifier.slice(0, appIdSeparator) : "",
    profileBundlePattern,
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
  if (profileInfo.type === "app-store" && profileInfo.hasWildcardAppId) {
    const error = new Error("App Store Connect yêu cầu Explicit App ID. Wildcard Profile chỉ dùng cho các luồng phân phối được Apple cho phép; hãy chọn profile Explicit đúng Bundle ID.");
    error.code = "APP_STORE_REQUIRES_EXPLICIT_APP_ID";
    throw error;
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
const APP_ID_PATTERN_COMPONENTS = /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/;

function parseProfileApplicationIdentifier(applicationIdentifier) {
  if (typeof applicationIdentifier !== "string" || !applicationIdentifier.trim()) return null;
  const value = applicationIdentifier.trim();
  const separator = value.indexOf(".");
  if (separator < 1 || separator === value.length - 1) return null;

  const appIdPrefix = value.slice(0, separator);
  const profileBundlePattern = value.slice(separator + 1);
  if (!/^[A-Za-z0-9-]+$/.test(appIdPrefix)) return null;

  if (profileBundlePattern === "*") {
    return { appIdPrefix, profileBundlePattern, appIdType: "wildcard", wildcardBase: "" };
  }

  if (!profileBundlePattern.includes("*")) {
    if (!BUNDLE_IDENTIFIER_PATTERN.test(profileBundlePattern)) return null;
    return { appIdPrefix, profileBundlePattern, appIdType: "explicit", wildcardBase: null };
  }

  // Apple's wildcard App ID is a terminal wildcard only. Examples:
  // TEAMID.com.example.* and TEAMID.*. It matches IDs beginning with the
  // fixed prefix plus a dot, not the fixed prefix itself.
  if (!profileBundlePattern.endsWith(".*") || (profileBundlePattern.match(/\*/g) || []).length !== 1) return null;
  const wildcardBase = profileBundlePattern.slice(0, -2);
  if (!wildcardBase || !APP_ID_PATTERN_COMPONENTS.test(wildcardBase)) return null;
  return { appIdPrefix, profileBundlePattern, appIdType: "wildcard", wildcardBase };
}

/** Return detailed, non-secret information about one profile App ID match. */
export function matchBundleIdentifierToApplicationIdentifier(applicationIdentifier, bundleIdentifier) {
  const bundleId = typeof bundleIdentifier === "string" ? bundleIdentifier.trim() : "";
  const parsed = parseProfileApplicationIdentifier(applicationIdentifier);
  if (!BUNDLE_IDENTIFIER_PATTERN.test(bundleId) || !parsed) {
    return {
      matched: false,
      appIdType: parsed?.appIdType || "unknown",
      appIdPrefix: parsed?.appIdPrefix || null,
      profileBundlePattern: parsed?.profileBundlePattern || (typeof applicationIdentifier === "string" ? applicationIdentifier : null),
      matchReason: "INVALID_APP_ID_OR_BUNDLE_ID",
    };
  }

  if (parsed.appIdType === "explicit") {
    const matched = parsed.profileBundlePattern === bundleId;
    return {
      matched,
      appIdType: "explicit",
      appIdPrefix: parsed.appIdPrefix,
      profileBundlePattern: parsed.profileBundlePattern,
      matchReason: matched ? "EXPLICIT_APP_ID_EXACT_MATCH" : "EXPLICIT_APP_ID_MISMATCH",
    };
  }

  const matched = parsed.wildcardBase === ""
    ? true
    : bundleId.startsWith(`${parsed.wildcardBase}.`) && bundleId.length > parsed.wildcardBase.length + 1;
  return {
    matched,
    appIdType: "wildcard",
    appIdPrefix: parsed.appIdPrefix,
    profileBundlePattern: parsed.profileBundlePattern,
    matchReason: matched ? "WILDCARD_APP_ID_MATCH" : "WILDCARD_APP_ID_PREFIX_MISMATCH",
  };
}

/**
 * Evaluate every application-identifier entitlement present in a profile.
 * This matters for Mac Catalyst profiles that can include both keys. All
 * provided identifiers must authorize the exact original Bundle ID.
 */
export function evaluateProvisioningProfileBundleCompatibility(profileOrIdentifiers, bundleIdentifier) {
  const identifiers = Array.isArray(profileOrIdentifiers)
    ? profileOrIdentifiers
    : profileOrIdentifiers && typeof profileOrIdentifiers === "object"
      ? (Array.isArray(profileOrIdentifiers.applicationIdentifiers) && profileOrIdentifiers.applicationIdentifiers.length
          ? profileOrIdentifiers.applicationIdentifiers
          : [profileOrIdentifiers.applicationIdentifier || profileOrIdentifiers.Entitlements?.["application-identifier"] || profileOrIdentifiers.Entitlements?.["com.apple.application-identifier"]])
      : [profileOrIdentifiers];
  const uniqueIdentifiers = [...new Set(identifiers.filter((value) => typeof value === "string" && value.trim()).map((value) => value.trim()))];
  const matches = uniqueIdentifiers.map((identifier) => ({
    applicationIdentifier: identifier,
    ...matchBundleIdentifierToApplicationIdentifier(identifier, bundleIdentifier),
  }));
  const compatible = matches.length > 0 && matches.every((item) => item.matched);
  const appIdTypes = [...new Set(matches.map((item) => item.appIdType))];
  return {
    compatible,
    bundleIdentifier: typeof bundleIdentifier === "string" ? bundleIdentifier.trim() : null,
    appIdType: appIdTypes.length === 1 ? appIdTypes[0] : appIdTypes.length ? "mixed" : "unknown",
    matchMode: compatible ? (appIdTypes.length === 1 ? appIdTypes[0].toUpperCase() : "MULTIPLE_APP_ID_ENTITLEMENTS") : "NO_MATCH",
    matches,
  };
}

/** Backwards-compatible boolean helper used by tests and API integrations. */
export function isBundleIdentifierAllowed(applicationIdentifier, bundleIdentifier) {
  return evaluateProvisioningProfileBundleCompatibility(applicationIdentifier, bundleIdentifier).compatible;
}

/** Fail early, before consuming quota or invoking ZSign, with safe diagnostics. */
export function getApplicationIdentifierParts(applicationIdentifier) {
  const parsed = parseProfileApplicationIdentifier(applicationIdentifier);
  if (!parsed) return null;
  return { appIdPrefix: parsed.appIdPrefix, profileBundlePattern: parsed.profileBundlePattern };
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

export function assertBundleIdentifierAllowed(applicationIdentifierOrList, bundleIdentifier, profileInfo = {}) {
  const compatibility = evaluateProvisioningProfileBundleCompatibility(applicationIdentifierOrList, bundleIdentifier);
  if (compatibility.compatible) return true;

  const matches = compatibility.matches;
  const first = matches[0] || {};
  const applicationIdentifier = matches.map((item) => item.applicationIdentifier).join("; ") || "(thiếu)";
  const profileBundlePattern = first.profileBundlePattern || "(không đọc được)";
  const appIdPrefix = first.appIdPrefix || null;
  const error = new Error(
    `Provisioning Profile không cấp quyền cho Bundle ID gốc của IPA. IPA: "${String(bundleIdentifier || "(trống)")}"; App ID trong profile: "${applicationIdentifier}". Worker tự nhận diện cả Explicit và Wildcard App ID nhưng profile này không khớp. Hãy chọn profile có App ID phù hợp; không đổi Bundle ID hoặc bỏ qua entitlement.`,
  );
  error.code = "BUNDLE_ID_PROFILE_MISMATCH";
  error.details = {
    bundleIdentifier: typeof bundleIdentifier === "string" ? bundleIdentifier : null,
    sourceBundleIdentifier: typeof bundleIdentifier === "string" ? bundleIdentifier : null,
    applicationIdentifier: matches.length <= 1 ? (matches[0]?.applicationIdentifier || null) : matches.map((item) => item.applicationIdentifier),
    applicationIdentifiers: matches.map((item) => item.applicationIdentifier),
    appIdPrefix,
    profileBundlePattern,
    appIdType: compatibility.appIdType,
    matchMode: compatibility.matchMode,
    matches,
    profileName: profileInfo.profileName || null,
    profileUuid: profileInfo.profileUuid || null,
    teamIdentifiers: Array.isArray(profileInfo.teamIdentifiers) ? profileInfo.teamIdentifiers : [],
    policy: "PRESERVE_SOURCE_BUNDLE_ID",
    nextAction: "SELECT_EXPLICIT_MATCH_OR_VALID_WILDCARD_PROFILE",
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
