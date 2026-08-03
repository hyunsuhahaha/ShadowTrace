// Gitea's user table stores passwd/salt as separate hex columns rather than
// a single self-describing string, so a raw `sqlite3 gitea.db` dump isn't
// directly usable by hashcat -m 10900 — the hex needs re-encoding to
// base64 and joining into "sha256:<iterations>:<b64 salt>:<b64 hash>" first.
// Gitea's default PBKDF2 iteration count is 50000 (PASSWORD_HASH_ALGO
// pbkdf2_hmac in app.ini), overridable since some installs configure it.
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) throw new Error("invalid hex");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) bytes[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary);
}

export function giteaHashToHashcatLine(
  passwdHex: string, saltHex: string, iterations = "50000",
): string | undefined {
  if (!passwdHex.trim() || !saltHex.trim() || !iterations.trim()) return undefined;
  try {
    const hashB64 = bytesToBase64(hexToBytes(passwdHex));
    const saltB64 = bytesToBase64(hexToBytes(saltHex));
    return `sha256:${iterations.trim()}:${saltB64}:${hashB64}`;
  } catch {
    return undefined;
  }
}
