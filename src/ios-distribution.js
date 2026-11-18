
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

  return {
    type,
    registeredDeviceCount: provisionedDevices.length,
    provisionedDevices,
    expiresAt: expirationDate && Number.isFinite(expirationDate.getTime())
      ? expirationDate.toISOString()
      : null,
    applicationIdentifier: typeof profile?.Entitlements?.["application-identifier"] === "string"
      ? profile.Entitlements["application-identifier"]
      : "",
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


/** Validate an optional target device against the registered device list in a signed profile. */
export function assertTargetDeviceAllowed(profileInfo, targetUdid) {
  const normalized = typeof targetUdid === "string" ? targetUdid.trim().toUpperCase() : "";
  if (!normalized) return { provided: false, registered: null };
  if (!/^[A-F0-9]{40}$/.test(normalized)) {
    const error = new Error("UDID phải gồm đúng 40 ký tự hexadecimal (0-9, A-F). ");
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

export function isBundleIdentifierAllowed(applicationIdentifier, bundleIdentifier) {
  if (typeof applicationIdentifier !== "string" || !applicationIdentifier.trim()) return false;
  if (typeof bundleIdentifier !== "string" || !bundleIdentifier.trim()) return false;

  // Apple application-identifier is normally TEAMID.bundle.identifier.
  const separator = applicationIdentifier.indexOf(".");
  if (separator < 1 || separator === applicationIdentifier.length - 1) return false;
  const profilePattern = applicationIdentifier.slice(separator + 1);
  if (profilePattern === "*" || profilePattern === bundleIdentifier) return true;
  if (profilePattern.endsWith(".*")) {
    return bundleIdentifier.startsWith(profilePattern.slice(0, -1));
  }
  return false;
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
