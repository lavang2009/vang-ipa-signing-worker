const IGNORED_METADATA_NAMES = new Set([
  ".ds_store",
  "thumbs.db",
  "desktop.ini",
]);

function isArchiveMetadata(parts) {
  return parts.some((part) => {
    const name = part.toLowerCase();
    return (
      name === "__macosx" ||
      name === ".appledouble" ||
      name === ".spotlight-v100" ||
      name === ".trashes" ||
      IGNORED_METADATA_NAMES.has(name) ||
      name.startsWith("._")
    );
  });
}

/**
 * Locate exactly one signing identity (.p12/.pfx) and one provisioning
 * profile (.mobileprovision) anywhere in a ZIP archive.
 *
 * The archive may contain a wrapper folder, nested folders, README files,
 * and common Finder/Windows metadata. Only the two credential entries are
 * extracted later; all other entries remain unused.
 */
export function validateCertificateArchiveEntries(entries) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error("ZIP chứng chỉ không có dữ liệu hoặc không đọc được danh sách tệp.");
  }

  const files = [];

  for (const rawEntry of entries) {
    if (typeof rawEntry !== "string" || rawEntry.length === 0) continue;

    // Reject alternate separators and absolute paths instead of trying to
    // reinterpret them differently on Windows and Linux.
    if (
      rawEntry.includes("\\") ||
      rawEntry.startsWith("/") ||
      /^[a-z]:/i.test(rawEntry) ||
      rawEntry.includes("\0")
    ) {
      throw new Error("ZIP chứa đường dẫn tệp không hợp lệ.");
    }

    const isDirectory = rawEntry.endsWith("/");
    const rawParts = rawEntry.split("/");
    if (isDirectory) rawParts.pop();

    // ZIP files created with `zip -r archive.zip .` commonly prefix every
    // entry with './'. Ignore only leading './' segments; reject traversal
    // or dot segments anywhere else.
    while (rawParts[0] === ".") rawParts.shift();
    if (rawParts.length === 0) continue;
    if (rawParts.some((part) => !part || part === "." || part === ".." || part.startsWith("-"))) {
      throw new Error("ZIP chứa đường dẫn tệp không an toàn.");
    }

    if (isArchiveMetadata(rawParts)) continue;
    if (isDirectory) continue;

    files.push({ entry: rawEntry, parts: rawParts });
  }

  const p12Files = files.filter(({ entry }) => /\.(p12|pfx)$/i.test(entry));
  const profileFiles = files.filter(({ entry }) => /\.mobileprovision$/i.test(entry));

  if (p12Files.length === 0) {
    throw new Error("Không tìm thấy chứng chỉ .p12 hoặc .pfx trong ZIP. Hãy kiểm tra lại tệp chứng chỉ.");
  }
  if (profileFiles.length === 0) {
    throw new Error("Không tìm thấy provisioning profile .mobileprovision trong ZIP.");
  }
  if (p12Files.length > 1) {
    throw new Error("ZIP chứa nhiều file .p12/.pfx. Chỉ giữ lại đúng một chứng chỉ cần dùng.");
  }
  if (profileFiles.length > 1) {
    throw new Error("ZIP chứa nhiều file .mobileprovision. Chỉ giữ lại đúng một provisioning profile cần dùng.");
  }

  return {
    p12Entry: p12Files[0].entry,
    profileEntry: profileFiles[0].entry,
  };
}
