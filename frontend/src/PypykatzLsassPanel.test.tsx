// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import PypykatzLsassPanel from "./PypykatzLsassPanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body),
    { status, headers: { "Content-Type": "application/json" } }));
}

it("uploads the selected dump file and shows the extracted credentials", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe("/api/decoders/pypykatz-lsass");
    expect(init?.body).toBeInstanceOf(FormData);
    return response({
      installed: true,
      raw_output: "== LogonSession ==\nusername: Administrator\nNThash: aad3b435b\n",
    });
  });
  vi.stubGlobal("fetch", fetcher);
  render(<PypykatzLsassPanel />);

  const input = screen.getByLabelText("LSASS 덤프 파일") as HTMLInputElement;
  const file = new File([new Uint8Array([0x4d, 0x44, 0x4d, 0x50])], "lsass.dmp");
  fireEvent.change(input, { target: { files: [file] } });
  fireEvent.click(screen.getByText("업로드 및 분석"));

  await waitFor(() => expect(screen.getByText(/Administrator/)).toBeTruthy());
});

it("shows an install hint when pypykatz is missing", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response({ installed: false, raw_output: "" })));
  render(<PypykatzLsassPanel />);

  const input = screen.getByLabelText("LSASS 덤프 파일") as HTMLInputElement;
  const file = new File([new Uint8Array([0x4d, 0x44])], "lsass.dmp");
  fireEvent.change(input, { target: { files: [file] } });
  fireEvent.click(screen.getByText("업로드 및 분석"));

  await waitFor(() => expect(screen.getByText(/설치되어 있지 않습니다/)).toBeTruthy());
});

it("disables the button until a file is chosen", () => {
  render(<PypykatzLsassPanel />);
  expect((screen.getByText("업로드 및 분석") as HTMLButtonElement).disabled).toBe(true);
});
