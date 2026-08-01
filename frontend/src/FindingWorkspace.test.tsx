// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import FindingWorkspace from "./FindingWorkspace";

const response = (body: unknown, status = 200) => Promise.resolve(new Response(
  status === 204 ? null : JSON.stringify(body),
  { status, headers: { "Content-Type": "application/json" } },
));

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it("supports scoped triage, CVSS feedback, and safe evidence defaults", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("/api/findings?")) return response([]);
    if (url.includes("/api/evidence?")) return response([
      { id: 8, target_id: 2, title: "FTP banner", kind: "command_output", sensitivity: "normal" },
      { id: 9, target_id: 2, title: "Credential dump", kind: "screenshot", sensitivity: "secret" },
    ]);
    if (url.includes("/api/targets?")) return response([
      { id: 2, name: "fileserver", ip: "10.10.10.20" },
    ]);
    if (url.includes("/targets/2/services")) return response([
      { id: 3, target_id: 2, port: 21, protocol: "tcp", name: "ftp" },
    ]);
    if (url.includes("/finding-templates")) return response([]);
    if (url.includes("/finding-summary")) return response({
      total: 0, open: 0, severity: {
        Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0,
      },
    });
    if (url.includes("/api/cvss?")) return response({ score: 9.8, severity: "Critical" });
    if (url.endsWith("/api/findings") && init?.method === "POST")
      return response({ ...JSON.parse(String(init.body)), id: 11, cvss_score: "9.8", severity: "Critical" }, 201);
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><FindingWorkspace projectId={1} /></QueryClientProvider>);

  await screen.findByText("10.10.10.20");
  fireEvent.click(screen.getByText("10.10.10.20").closest("label")!
    .querySelector('input[type="checkbox"]')!);
  expect(await screen.findByText("21/tcp")).toBeTruthy();
  fireEvent.click(screen.getByText("Credential dump").closest("button")!);
  expect(screen.getByLabelText(/Credential dump 캡션/)).toBeTruthy();
  expect((screen.getByText("Credential dump").closest("article")!
    .querySelector('input[type="checkbox"]') as HTMLInputElement).disabled).toBe(true);

  fireEvent.change(screen.getByPlaceholderText("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), {
    target: { value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" },
  });
  fireEvent.click(screen.getByText("검증·계산"));
  expect(await screen.findByText("CVSS 9.8 · Critical로 계산했습니다.")).toBeTruthy();
  fireEvent.change(screen.getByPlaceholderText(/Anonymous FTP access/), { target: { value: "Anonymous FTP" } });
  fireEvent.click(screen.getByText("저장"));
  await waitFor(() => expect(fetcher.mock.calls.some(
    ([url, init]) => String(url).endsWith("/api/findings") && init?.method === "POST",
  )).toBe(true));
});
