// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import RoundcubeDesDecoder from "./RoundcubeDesDecoder";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body),
    { status, headers: { "Content-Type": "application/json" } }));
}

it("posts the key and blob to the backend and shows the returned plaintext", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    expect(String(input)).toBe("/api/decoders/roundcube-des");
    expect(JSON.parse(String(init?.body))).toEqual({
      key: "rcmail-!24ByteDESkey*Str", value: "hcVCSNXOYgUXvhArn1a1OHJtDck+CFME",
    });
    return response({ plaintext: "595mO8DmwGeD" });
  });
  vi.stubGlobal("fetch", fetcher);
  render(<RoundcubeDesDecoder />);

  fireEvent.change(screen.getByLabelText("des_key"), {
    target: { value: "rcmail-!24ByteDESkey*Str" } });
  fireEvent.change(screen.getByLabelText("암호화된 값"), {
    target: { value: "hcVCSNXOYgUXvhArn1a1OHJtDck+CFME" } });

  await waitFor(() => expect(screen.getByText("595mO8DmwGeD")).toBeTruthy());
});

it("shows a failure message when the backend can't decrypt the value", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response({ plaintext: null })));
  render(<RoundcubeDesDecoder />);

  fireEvent.change(screen.getByLabelText("des_key"), { target: { value: "short-key" } });
  fireEvent.change(screen.getByLabelText("암호화된 값"), { target: { value: "not-valid" } });

  await waitFor(() => expect(screen.getByText(/복호화 실패/)).toBeTruthy());
});
