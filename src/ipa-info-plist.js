import { parse as parsePlist } from "plist";

const BINARY_PLIST_MAGIC = "bplist00";

function invalidInfoPlist(message, cause, format = "UNKNOWN", byteLength = 0) {
  const error = new Error(message);
  error.code = "INVALID_IPA_INFO_PLIST";
  error.payloadFormat = format;
  error.payloadBytes = byteLength;
  if (cause) error.cause = cause;
  return error;
}

/**
 * Parse an app's Info.plist without guessing that every byte buffer is binary.
 * The plist package expects XML/OpenStep as strings and binary plists as bytes.
 */
export function parseIpaInfoPlist(input) {
  const bytes = Buffer.from(input || []);
  if (!bytes.length) {
    throw invalidInfoPlist("IPA chứa Info.plist rỗng.", null, "EMPTY", 0);
  }

  const magic = bytes.subarray(0, 8).toString("ascii");
  let value;
  let format;

  try {
    if (magic === BINARY_PLIST_MAGIC) {
      format = "BINARY_PLIST";
      value = parsePlist(new Uint8Array(bytes));
    } else {
      // XML plist may begin with a UTF-8 BOM or whitespace. OpenStep plist
      // is also textual and is supported by plist.js.
      const text = bytes.toString("utf8").replace(/^\uFEFF/, "").trimStart();
      if (/^(?:<\?xml\b|<plist\b)/i.test(text)) {
        format = "XML_PLIST";
        value = parsePlist(text);
      } else if (/^[({]/.test(text)) {
        format = "OPENSTEP_PLIST";
        value = parsePlist(text);
      } else {
        const prefix = bytes.subarray(0, 8).toString("hex");
        throw invalidInfoPlist(
          `IPA chứa Info.plist có định dạng không được nhận diện (header ${prefix || "empty"}, ${bytes.length} byte).`,
          null,
          "UNKNOWN",
          bytes.length,
        );
      }
    }
  } catch (cause) {
    if (cause?.code === "INVALID_IPA_INFO_PLIST") throw cause;
    throw invalidInfoPlist(
      `Không thể phân tích Info.plist trong IPA (${format || "UNKNOWN"}, ${bytes.length} byte).`,
      cause,
      format || "UNKNOWN",
      bytes.length,
    );
  }

  if (!value || typeof value !== "object" || Array.isArray(value) || Buffer.isBuffer(value) || value instanceof Uint8Array) {
    throw invalidInfoPlist(
      `Info.plist trong IPA phải là dictionary, nhận được ${format}.`,
      null,
      format,
      bytes.length,
    );
  }

  return { value, format, byteLength: bytes.length };
}
