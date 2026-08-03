// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import VncPasswordDecoder from "./VncPasswordDecoder";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body),
    { status, headers: { "Content-Type": "application/json" } }));
}

it("posts the pasted hex value and shows the returned plaintext", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe("/api/decoders/vnc-password");
    expect(JSON.parse(String(init?.body))).toEqual({ ciphertext_hex: "6bcf2a4b6e5aca7f" });
    return response({ plaintext: "s3cr3t12" });
  });
  vi.stubGlobal("fetch", fetcher);
  render(<VncPasswordDecoder />);

  fireEvent.change(screen.getByLabelText("VNC 비밀번호 값 (hex)"), {
    target: { value: "6bcf2a4b6e5aca7f" },
  });

  await waitFor(() => expect(screen.getByText("s3cr3t12")).toBeTruthy());
});

it("shows a failure message when the backend can't decode the value", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response({ plaintext: null })));
  render(<VncPasswordDecoder />);

  fireEvent.change(screen.getByLabelText("VNC 비밀번호 값 (hex)"), {
    target: { value: "not-valid" },
  });

  await waitFor(() => expect(screen.getByText(/복호화 실패/)).toBeTruthy());
});
