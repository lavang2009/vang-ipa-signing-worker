export function validateCertificateArchiveEntries(entries) {
  const cleaned = entries.filter((entry) => !entry.startsWith("__MACOSX/") && !entry.endsWith("/.DS_Store") && entry !== ".DS_Store");
  const topFolders = new Set();
  const files = [];
  for (const entry of cleaned) {
    if (entry.includes("\\") || entry.startsWith("/") || entry.includes("\0")) throw new Error("ZIP chứa đường dẫn tệp không hợp lệ.");
    const isDirectory = entry.endsWith("/");
    const parts = entry.split("/").filter(Boolean);
    if (!parts.length || parts.some((part) => part === "." || part === ".." || part.startsWith("-"))) throw new Error("ZIP chứa đường dẫn tệp không an toàn.");
    topFolders.add(parts[0]);
    if (parts.length < 2) {
      if (isDirectory) continue;
      throw new Error("Mọi tệp trong ZIP phải nằm bên trong hai thư mục chứng chỉ.");
    }
    if (isDirectory) throw new Error("ZIP chỉ được có đúng hai thư mục cấp cao nhất, không tạo thêm thư mục con.");
    files.push({ entry, parts });
  }
  if (topFolders.size !== 2) throw new Error("ZIP chứng chỉ phải chứa đúng hai thư mục cấp cao nhất: một thư mục P12/PFX và một thư mục MobileProvision.");
  if (files.length !== 2) throw new Error("ZIP chỉ được chứa hai tệp cần thiết: một P12/PFX và một mobileprovision, mỗi tệp nằm trong một thư mục riêng.");
  const p12Files = files.filter(({ entry }) => /\.(p12|pfx)$/i.test(entry));
  const profileFiles = files.filter(({ entry }) => /\.mobileprovision$/i.test(entry));
  if (p12Files.length !== 1) throw new Error("Cần có đúng một file .p12 hoặc .pfx trong một trong hai thư mục ZIP.");
  if (profileFiles.length !== 1) throw new Error("Cần có đúng một file .mobileprovision trong thư mục còn lại của ZIP.");
  if (p12Files[0].parts.length !== 2 || profileFiles[0].parts.length !== 2) throw new Error("Đặt trực tiếp file P12/PFX và mobileprovision bên trong mỗi thư mục, không tạo thêm thư mục con.");
  if (p12Files[0].parts[0] === profileFiles[0].parts[0]) throw new Error("File P12/PFX và mobileprovision phải nằm trong hai thư mục khác nhau.");
  return { p12Entry: p12Files[0].entry, profileEntry: profileFiles[0].entry };
}
