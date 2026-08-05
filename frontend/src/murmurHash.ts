// MurmurHash3 x86_32 (seed 0), returned as a signed 32-bit int -- matches
// the reference C++ implementation and Python's mmh3.hash(), byte-for-byte
// verified against mmh3 across empty/short/long/binary inputs.
export function murmurHash3_32(bytes: Uint8Array, seed = 0): number {
  let h1 = seed;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const len = bytes.length;
  const nblocks = len >> 2;

  for (let i = 0; i < nblocks; i++) {
    let k1 = bytes[i * 4] | (bytes[i * 4 + 1] << 8) | (bytes[i * 4 + 2] << 16) |
      (bytes[i * 4 + 3] << 24);
    k1 = Math.imul(k1, c1);
    k1 = (k1 << 15) | (k1 >>> 17);
    k1 = Math.imul(k1, c2);
    h1 ^= k1;
    h1 = (h1 << 13) | (h1 >>> 19);
    h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0;
  }

  let k1 = 0;
  const tailIndex = nblocks * 4;
  switch (len & 3) {
    case 3: k1 ^= bytes[tailIndex + 2] << 16; // falls through
    case 2: k1 ^= bytes[tailIndex + 1] << 8; // falls through
    case 1:
      k1 ^= bytes[tailIndex];
      k1 = Math.imul(k1, c1);
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 = Math.imul(k1, c2);
      h1 ^= k1;
  }

  h1 ^= len;
  h1 ^= h1 >>> 16;
  h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13;
  h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;

  return h1 | 0;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

// Shodan/censys's http.favicon.hash (and every "favicon-hash.py" clone) is
// mmh3.hash(codecs.encode(favicon_bytes, "base64")) -- Python's legacy
// base64 codec, which line-wraps the output at 76 characters with a
// trailing newline after every line including the last. The wrapping
// matters: hashing plain unwrapped base64 gives a different, non-matching
// value.
export function shodanFaviconHash(bytes: Uint8Array): number {
  const base64 = bytesToBase64(bytes);
  let wrapped = "";
  for (let i = 0; i < base64.length; i += 76) wrapped += base64.slice(i, i + 76) + "\n";
  return murmurHash3_32(new TextEncoder().encode(wrapped));
}
