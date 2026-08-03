// Windows 10+ Recycle Bin index files ($I<random>, paired with the actual
// deleted content in $R<random>) are a fixed little-endian binary layout:
//   0..7   header/version (2 for Windows 10+)
//   8..15  original file size (int64)
//   16..23 deletion time as a Windows FILETIME (100ns ticks since 1601-01-01)
//   24..27 original path length, in UTF-16 code units (int32)
//   28..   original path, UTF-16LE
// Only the Windows 10+ layout (version 2) is handled — Vista/7's $I format
// has no length field and a fixed 260-char path, and guessing at that
// layout instead of rejecting it would risk silently misparsing bytes.
const FILETIME_UNIX_EPOCH_DIFF_100NS = 116444736000000000n;

export type RecycleBinEntry = {
  originalSize: bigint;
  deletedAt: Date;
  originalPath: string;
};

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function parseRecycleBinIndex(base64: string): RecycleBinEntry | undefined {
  if (!base64.trim()) return undefined;
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(base64);
  } catch {
    return undefined;
  }
  if (bytes.length < 28) return undefined;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = view.getBigUint64(0, true);
  if (version !== 2n) return undefined;
  const originalSize = view.getBigInt64(8, true);
  const filetime = view.getBigUint64(16, true);
  const pathLength = view.getInt32(24, true);
  const pathBytes = pathLength * 2;
  if (pathLength <= 0 || 28 + pathBytes > bytes.length) return undefined;
  const codeUnits = new Uint16Array(bytes.buffer, bytes.byteOffset + 28, pathLength);
  const originalPath = String.fromCharCode(...codeUnits).replace(/\0+$/, "");
  const unixMillis = Number((filetime - FILETIME_UNIX_EPOCH_DIFF_100NS) / 10000n);
  return { originalSize, deletedAt: new Date(unixMillis), originalPath };
}
