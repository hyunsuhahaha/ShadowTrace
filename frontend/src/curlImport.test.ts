import { describe, expect, it } from "vitest";
import { parseCurl } from "./curlImport";

describe("curl import", () => {
  it("parses a multi-line Chrome-style POST with a Cookie header split out separately", () => {
    const result = parseCurl(`curl 'http://10.129.219.134/login.php' \\
  -H 'Content-Type: application/x-www-form-urlencoded' \\
  -H 'Cookie: PHPSESSID=abc123; theme=dark' \\
  --data-raw 'username=admin&password=letmein123'`);

    expect(result).toEqual({
      method: "POST",
      url: "http://10.129.219.134/login.php",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      cookies: { PHPSESSID: "abc123", theme: "dark" },
      body: "username=admin&password=letmein123",
    });
  });

  it("defaults to GET with no headers or body when nothing else is given", () => {
    const result = parseCurl("curl 'http://10.129.219.134/'");

    expect(result).toEqual({
      method: "GET", url: "http://10.129.219.134/", headers: {}, cookies: {}, body: "",
    });
  });

  it("keeps an explicit -X method even when --data is present", () => {
    const result = parseCurl(`curl -X PUT 'http://10.129.219.134/api/1' --data '{"a":1}'`);

    expect(result?.method).toBe("PUT");
    expect(result?.body).toBe('{"a":1}');
  });

  it("reads cookies from -b as well as a Cookie header", () => {
    const result = parseCurl("curl 'http://x/login' -X POST -b 'PHPSESSID=abc123' --data-raw 'a=1'");

    expect(result?.cookies).toEqual({ PHPSESSID: "abc123" });
  });

  it("skips flags that take a value so they aren't mistaken for the URL", () => {
    const result = parseCurl("curl -A 'Mozilla/5.0' 'http://x/' --compressed");

    expect(result?.url).toBe("http://x/");
    expect(result?.headers).toEqual({});
  });

  it("returns undefined for input that isn't a curl command", () => {
    expect(parseCurl("GET / HTTP/1.1\nHost: x")).toBeUndefined();
    expect(parseCurl("")).toBeUndefined();
  });
});
