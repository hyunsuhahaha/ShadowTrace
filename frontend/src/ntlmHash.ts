// Matches Responder/ntlmrelayx-style NetNTLMv2-SSP capture lines regardless
// of the protocol label prefix ("[SMB] NTLMv2-SSP Hash : ", "[HTTP] NTLMv2 ...",
// etc.) -- the shape (user::domain:challenge:proof:blob) is what identifies
// it, matching the same detect regex the hash-cracking catalog uses for its
// netntlmv2 mode, so a match here is guaranteed to paste in cleanly there.
const NTLMV2_PATTERN = /[^\s:]+::[^\s:]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]+/g;

export function extractNtlmv2Hashes(rawText: string): string[] {
  const text = rawText.replace(/\x1b\[[0-9;]*m/g, "");
  return [...new Set(text.match(NTLMV2_PATTERN) || [])];
}
