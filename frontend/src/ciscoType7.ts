// Cisco "type 7" passwords aren't hashed — they're XORed against a fixed,
// publicly-known 53-byte key table (Cisco's own "Vigenère"-style
// obfuscation), starting at the offset given by the leading 2-digit seed.
// Unlike type 5 (md5crypt, already covered by the hash-cracking catalog),
// this needs no wordlist or brute force: it decodes instantly.
const XLAT = [
  0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
  0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36,
  0x39, 0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b,
  0x3b, 0x66, 0x67, 0x38, 0x37,
];

export function decodeCiscoType7(raw: string): string | undefined {
  const value = raw.trim();
  if (!/^\d{2}[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) return undefined;
  const seed = Number(value.slice(0, 2));
  if (seed >= XLAT.length) return undefined;
  const hexBody = value.slice(2);
  let plain = "";
  for (let i = 0; i < hexBody.length; i += 2) {
    const byte = parseInt(hexBody.slice(i, i + 2), 16);
    plain += String.fromCharCode(byte ^ XLAT[(seed + i / 2) % XLAT.length]);
  }
  return plain;
}
