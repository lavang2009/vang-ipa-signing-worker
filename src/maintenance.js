const DEFAULT_TITLE = "Công cụ ký IPA đang bảo trì";
const DEFAULT_MESSAGE = "Chúng tôi đang cập nhật hệ thống ký IPA. Vui lòng quay lại sau.";

export function normalizeIpaSigningMaintenance(data = {}) {
  return {
    enabled: data?.enabled === true,
    title: String(data?.title || DEFAULT_TITLE).trim().slice(0, 120),
    message: String(data?.message || DEFAULT_MESSAGE).trim().slice(0, 1200),
    estimatedReturn: String(data?.estimatedReturn || "").trim().slice(0, 120),
  };
}

export function isIpaSigningMaintenanceBlocked(maintenance, isAdmin = false) {
  return maintenance?.enabled === true && isAdmin !== true;
}
