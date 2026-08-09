// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { getNodeActivity, Inspector } from "./GraphWorkspace";

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});

it("parses only live graph activity metadata", () => {
  expect(getNodeActivity({ meta: JSON.stringify({ activity: {
    kind: "scan", status: "running", label: "Full TCP",
  } }) })).toEqual({ kind: "scan", status: "running", label: "Full TCP",
    startedAt: null });
  expect(getNodeActivity({ meta: JSON.stringify({ activity: {
    kind: "execution", status: "completed", label: "whatweb",
  } }) })).toBeNull();
  expect(getNodeActivity({ meta: "broken" })).toBeNull();
});

it("offers the full link-extract workflow from an execution node", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/executions/42/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "css/style.css\nhttps://cdn.example/app.js\n/index.php?page=german.html\n",
      stderr: "", status: "completed", error: "", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      { id: 10, ip: "10.10.11.80", hostname: "unika.htb" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets/10/services")) return Promise.resolve(new Response(JSON.stringify([
      { id: 20, port: 80, name: "http", tls: false },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/executions/42/derive") && init?.method === "POST")
      return Promise.resolve(new Response(JSON.stringify({ id: 7 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10, serviceId: 20 }} node={{
      id: "tech-1", type: "technique", status: "succeeded",
      label: "http-link-extract", objective: false, hidden: false,
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 42 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  await screen.findByText("/index.php?page=german.html");
  const result = screen.getByLabelText("링크 추출 결과");
  expect(result.textContent?.indexOf("/index.php?page=german.html"))
    .toBeLessThan(result.textContent?.indexOf("https://cdn.example/app.js") ?? 0);
  expect(result.textContent?.indexOf("https://cdn.example/app.js"))
    .toBeLessThan(result.textContent?.indexOf("css/style.css") ?? 0);

  const requestButtons = screen.getAllByText("Request 탭에 채우기");
  expect(requestButtons).toHaveLength(2);
  fireEvent.click(requestButtons[0]);
  expect(JSON.parse(localStorage.getItem("oscp-web-launch") || "null")).toEqual({
    targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=german.html",
  });

  fireEvent.click(screen.getByText("Evidence로 저장"));
  await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
    "/api/executions/42/derive", expect.objectContaining({ method: "POST" }),
  ));
  expect(await screen.findByText("Evidence로 저장됨")).toBeTruthy();
});

it("shows service context and logs for every execution node", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    const body = url.endsWith("/api/executions/77/output") ? {
      stdout: "HTTPServer[Microsoft-HTTPAPI/2.0]", stderr: "probe timed out once",
      status: "failed", error: "timeout", exit_code: 1,
    } : url.endsWith("/api/targets") ? [
      { id: 10, ip: "10.129.95.234" },
    ] : url.endsWith("/api/targets/10/services") ? [
      { id: 20, port: 5985, name: "http", product: "Microsoft HTTPAPI httpd", tls: false },
    ] : null;
    if (body === null) throw new Error(`Unhandled request: ${url}`);
    return Promise.resolve(new Response(JSON.stringify(body), {
      headers: { "Content-Type": "application/json" },
    }));
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10, serviceId: 20 }} node={{
      id: "tech-2", type: "technique", status: "attempt-failed",
      label: "http-whatweb", objective: false, hidden: false,
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 77 }),
      meta: JSON.stringify({ command: "whatweb http://10.129.95.234:5985" }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("10.129.95.234")).toBeTruthy();
  expect(screen.getByText("5985/tcp · http · Microsoft HTTPAPI httpd")).toBeTruthy();
  expect(screen.getByText("whatweb http://10.129.95.234:5985")).toBeTruthy();
  expect(screen.getByText("HTTPServer[Microsoft-HTTPAPI/2.0]")).toBeTruthy();
  expect(screen.getByText("probe timed out once")).toBeTruthy();
  expect(screen.getByText(/exit 1/)).toBeTruthy();
});
