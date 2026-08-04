// Parses a curl command copied from a browser's devtools Network tab
// (Chrome/Firefox "Copy as cURL") into the fields Web Testing's Request
// editor already has, so a captured login request doesn't need retyping.
export type CurlImportResult = {
  method: string;
  url: string;
  headers: Record<string, string>;
  cookies: Record<string, string>;
  body: string;
};

const VALUE_FLAGS = new Set(["-A", "--user-agent", "-e", "--referer", "-u", "--user", "-x", "--proxy"]);

function tokenize(input: string): string[] {
  const normalized = input.replace(/\\\r?\n\s*/g, " ").replace(/\^\r?\n\s*/g, " ").trim();
  const tokens: string[] = [];
  let i = 0;
  while (i < normalized.length) {
    const ch = normalized[i];
    if (/\s/.test(ch)) { i++; continue; }
    if (ch === "'") {
      const end = normalized.indexOf("'", i + 1);
      const stop = end === -1 ? normalized.length : end;
      tokens.push(normalized.slice(i + 1, stop));
      i = stop + 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1, value = "";
      while (j < normalized.length && normalized[j] !== '"') {
        if (normalized[j] === "\\" && j + 1 < normalized.length) { value += normalized[j + 1]; j += 2; continue; }
        value += normalized[j]; j++;
      }
      tokens.push(value);
      i = j + 1;
      continue;
    }
    let j = i;
    while (j < normalized.length && !/\s/.test(normalized[j])) j++;
    tokens.push(normalized.slice(i, j));
    i = j;
  }
  return tokens;
}

function parseCookieHeader(value: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const part of value.split(";")) {
    const sep = part.indexOf("=");
    if (sep === -1) continue;
    cookies[part.slice(0, sep).trim()] = part.slice(sep + 1).trim();
  }
  return cookies;
}

export function parseCurl(input: string): CurlImportResult | undefined {
  const tokens = tokenize(input);
  if (tokens[0] !== "curl") return undefined;
  let url = "", method = "", body = "", hasData = false;
  const headers: Record<string, string> = {};
  let cookies: Record<string, string> = {};
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    if ((token === "-X" || token === "--request") && tokens[i + 1] !== undefined) {
      method = tokens[++i].toUpperCase();
      continue;
    }
    if ((token === "-H" || token === "--header") && tokens[i + 1] !== undefined) {
      const header = tokens[++i];
      const sep = header.indexOf(":");
      if (sep === -1) continue;
      const name = header.slice(0, sep).trim();
      const value = header.slice(sep + 1).trim();
      if (name.toLowerCase() === "cookie") cookies = { ...cookies, ...parseCookieHeader(value) };
      else headers[name] = value;
      continue;
    }
    if ((token === "-b" || token === "--cookie") && tokens[i + 1] !== undefined) {
      cookies = { ...cookies, ...parseCookieHeader(tokens[++i]) };
      continue;
    }
    if (["-d", "--data", "--data-raw", "--data-binary", "--data-ascii"].includes(token)
      && tokens[i + 1] !== undefined) {
      body = tokens[++i];
      hasData = true;
      continue;
    }
    if (token === "--url" && tokens[i + 1] !== undefined) {
      url = tokens[++i];
      continue;
    }
    if (token.startsWith("-")) {
      if (VALUE_FLAGS.has(token) && tokens[i + 1] !== undefined) i++;
      continue;
    }
    if (!url) url = token;
  }
  if (!url) return undefined;
  return { method: method || (hasData ? "POST" : "GET"), url, headers, cookies, body };
}
