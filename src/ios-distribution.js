const DEVICE_UDID_PATTERN = /^[A-F0-9]{40}$/;

export function classifyProvisioningProfile(profile) {
  const provisionedDevices = Array.isArray(profile?.ProvisionedDevices)
    ? profile.ProvisionedDevices.filter((item) => typeof item === "string" && item.trim())
    : [];
  const provisionsAllDevices = profile?.ProvisionsAllDevices === true;
  const getTaskAllow = profile?.Entitlements?.["get-task-allow"];

  let type = "unknown";
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
  if (!profileInfo || profileInfo.type === "unknown") {
    throw new Error("Không xác định được loại Provisioning Profile. Hãy xuất lại profile hợp lệ từ Apple Developer.");
  }
  if (!profileInfo.expiresAt) {
    throw new Error("Provisioning Profile không có ngày hết hạn hợp lệ.");
  }
  if (new Date(profileInfo.expiresAt).getTime() <= now) {
    throw new Error("Provisioning Profile đã hết hạn. Hãy tạo và tải profile mới từ Apple Developer.");
  }
  if (profileInfo.type === "ad-hoc" && profileInfo.registeredDeviceCount < 1) {
    throw new Error("Ad Hoc Profile không có thiết bị được đăng ký. Hãy thêm UDID thiết bị vào profile rồi tải lại.");
  }
  return profileInfo;
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

export function normalizeDeviceUdid(value) {
  const normalized = String(value || "").replace(/[-\s]/g, "").toUpperCase();
  if (!normalized) return "";
  if (!DEVICE_UDID_PATTERN.test(normalized)) {
    throw new Error("UDID phải gồm 40 ký tự hex. Hãy kiểm tra lại UDID thiết bị.");
  }
  return normalized;
}

export function isDeviceRegistered(profileInfo, udid) {
  if (!udid) return null;
  return profileInfo?.provisionedDevices?.some((device) => String(device).toUpperCase() === udid) || false;
}
