// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import DpapiDecoderPanel from "./DpapiDecoderPanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body),
    { status, headers: { "Content-Type": "application/json" } }));
}

it("decrypts a masterkey and offers to feed the key into the credential step", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input) === "/api/decoders/dpapi-masterkey") {
      expect(JSON.parse(String(init?.body))).toEqual({
        masterkey_b64: "ZmFrZQ==", sid: "S-1-5-21-1-2-3-1000", password: "hunter2",
      });
      return response({ installed: true, decrypted_key: "deadbeefcafebabe", raw_output: "" });
    }
    throw new Error(`Unhandled request: ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<DpapiDecoderPanel />);

  fireEvent.change(screen.getByLabelText("마스터키 파일 (base64)"), { target: { value: "ZmFrZQ==" } });
  fireEvent.change(screen.getByLabelText("사용자 SID"), { target: { value: "S-1-5-21-1-2-3-1000" } });
  fireEvent.change(screen.getByLabelText("마스터키용 비밀번호"), { target: { value: "hunter2" } });
  fireEvent.click(screen.getByText("마스터키 복호화"));

  await waitFor(() => expect(screen.getByText("deadbeefcafebabe")).toBeTruthy());
  fireEvent.click(screen.getByText("아래 Credential 복호화에 사용"));
  expect((screen.getByLabelText("복호화된 마스터키 (hex)") as HTMLInputElement).value)
    .toBe("deadbeefcafebabe");
});

it("shows the credential decrypt result", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    if (String(input) === "/api/decoders/dpapi-credential") {
      return response({
        installed: true,
        raw_output: "username: steph.cooper_adm\npassword: FivethChipOnItsWay2025!\n",
      });
    }
    throw new Error(`Unhandled request: ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<DpapiDecoderPanel />);

  fireEvent.change(screen.getByLabelText("Credential 파일 (base64)"), {
    target: { value: "ZmFrZQ==" } });
  fireEvent.change(screen.getByLabelText("복호화된 마스터키 (hex)"), {
    target: { value: "deadbeefcafebabe" } });
  fireEvent.click(screen.getByText("Credential 복호화"));

  await waitFor(() => expect(screen.getByText(/steph\.cooper_adm/)).toBeTruthy());
});

it("shows an install hint when impacket-dpapi is missing", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response({
    installed: false, decrypted_key: null, raw_output: "",
  })));
  render(<DpapiDecoderPanel />);

  fireEvent.change(screen.getByLabelText("마스터키 파일 (base64)"), { target: { value: "ZmFrZQ==" } });
  fireEvent.change(screen.getByLabelText("사용자 SID"), { target: { value: "S-1-5-21-1-2-3-1000" } });
  fireEvent.change(screen.getByLabelText("마스터키용 비밀번호"), { target: { value: "hunter2" } });
  fireEvent.click(screen.getByText("마스터키 복호화"));

  await waitFor(() => expect(screen.getByText(/설치되어 있지 않습니다/)).toBeTruthy());
});
