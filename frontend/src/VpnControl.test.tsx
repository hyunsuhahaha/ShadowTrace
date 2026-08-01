// @vitest-environment jsdom
import React from "react";
import {cleanup, fireEvent, render, screen, waitFor} from "@testing-library/react";
import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {afterEach, expect, it, vi} from "vitest";
import VpnControl from "./VpnControl";

const response = (body: unknown) => Promise.resolve(new Response(
  JSON.stringify(body), {headers: {"Content-Type": "application/json"}},
));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("reviews the VPN file before connecting without exposing process output", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/vpn/status")) return response({
      connected: false, tun0: "", operation: {
        action: "status", stdout: "", stderr: "", exit_code: 0,
      },
    });
    if (url.endsWith("/api/vpn/prepare")) return response({
      approval_token: "a".repeat(43), file_name: "lab.ovpn",
      sha256: "b".repeat(64), profile_name: "oscp-workspace-bbbbbbbbbbbb",
      actions: ["NetworkManager profile import", "VPN connection up"],
    });
    if (url.endsWith("/api/vpn/connect") && init?.method === "POST")
      return response({connected: true, tun0: "tun0 10.10.0.2", operations: [
        {action: "import", stdout: "imported\n", stderr: "", exit_code: 0},
        {action: "up", stdout: "", stderr: "warning\n", exit_code: 4},
      ]});
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({
    defaultOptions: {queries: {retry: false, staleTime: Infinity}},
  });
  render(<QueryClientProvider client={client}><VpnControl /></QueryClientProvider>);
  const input = document.querySelector('input[type="file"]') as HTMLInputElement;
  fireEvent.change(input, {
    target: {files: [new File(["client\nremote test"], "lab.ovpn")]},
  });
  const dialog = await screen.findByRole("dialog", {name: "VPN 연결 승인"});
  expect(dialog.textContent).toContain("lab.ovpn");
  expect(dialog.textContent).toContain("b".repeat(64));
  expect(fetcher.mock.calls.some(([url]) =>
    String(url).endsWith("/api/vpn/connect"))).toBe(false);
  fireEvent.click(screen.getByText("확인 후 연결"));
  await waitFor(() => expect(fetcher.mock.calls.some(([url]) =>
    String(url).endsWith("/api/vpn/connect"))).toBe(true));
  expect(screen.queryByText("stdout")).toBeNull();
  expect(screen.queryByText("stderr")).toBeNull();
  expect(screen.queryByText(/warning/)).toBeNull();
});
