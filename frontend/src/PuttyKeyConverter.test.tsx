// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import PuttyKeyConverter from "./PuttyKeyConverter";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body),
    { status, headers: { "Content-Type": "application/json" } }));
}

it("posts pasted .ppk content and shows the converted OpenSSH key", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe("/api/decoders/putty-to-openssh");
    expect(JSON.parse(String(init?.body))).toEqual({
      ppk_content: "PuTTY-User-Key-File-3: ssh-rsa\nfake",
    });
    return response({
      installed: true,
      private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n",
    });
  });
  vi.stubGlobal("fetch", fetcher);
  render(<PuttyKeyConverter />);

  fireEvent.change(screen.getByLabelText(".ppk 파일 내용"), {
    target: { value: "PuTTY-User-Key-File-3: ssh-rsa\nfake" },
  });

  await waitFor(() => expect(screen.getByText(/BEGIN OPENSSH PRIVATE KEY/)).toBeTruthy(),
    { timeout: 2000 });
});

it("shows a failure message when conversion fails", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response({
    installed: true, private_key: null, stderr: "puttygen: unable to parse",
  })));
  render(<PuttyKeyConverter />);

  fireEvent.change(screen.getByLabelText(".ppk 파일 내용"), { target: { value: "not a key" } });

  await waitFor(() => expect(screen.getByText(/변환 실패/)).toBeTruthy(), { timeout: 2000 });
});

it("shows an install hint when puttygen is missing", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response({ installed: false, private_key: null })));
  render(<PuttyKeyConverter />);

  fireEvent.change(screen.getByLabelText(".ppk 파일 내용"), {
    target: { value: "PuTTY-User-Key-File-3: ssh-rsa\nfake" },
  });

  await waitFor(() => expect(screen.getByText(/설치되어 있지 않습니다/)).toBeTruthy(),
    { timeout: 2000 });
});
