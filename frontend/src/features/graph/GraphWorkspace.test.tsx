// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { getNodeActivity, GraphRequestPanel, initialGraphPosition, Inspector,
  initialGraphPositionNearParent, isCrackableCredential, buildActivityFeed, clampActivityPanel,
  filterActivityFeed, nodeStatusReason, nodeSummary } from "./GraphWorkspace";

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
  expect(getNodeActivity({ meta: JSON.stringify({ activity: {
    kind: "listener", status: "launched", label: "RESPONDER",
  } }) })?.kind).toBe("listener");
});

it("routes hash credentials to cracking instead of post-exploitation", () => {
  expect(isCrackableCredential({ type: "credential",
    meta: JSON.stringify({ credType: "hash" }) })).toBe(true);
  expect(isCrackableCredential({ type: "credential",
    meta: JSON.stringify({ credType: "password" }) })).toBe(false);
});

it("preserves settled node positions when graph topology changes", () => {
  const settled = new Map([["host-1", { x: 712, y: 418 }]]);
  expect(initialGraphPosition("host-1", 0, 2, settled)).toEqual({ x: 712, y: 418 });
  expect(initialGraphPosition("service-new", 1, 2, settled)).not.toEqual({ x: 712, y: 418 });
  const child = initialGraphPositionNearParent("execution-42", settled.get("host-1"));
  expect(Math.hypot(child!.x - 712, child!.y - 418)).toBeCloseTo(74);
});

it("summarizes node outcomes and incomplete reasons without empty glyphs", () => {
  expect(nodeSummary({ type: "service", status: "untried", label: "80/tcp http",
    meta: JSON.stringify({ product: "Apache httpd", version: "2.4.52" }) }))
    .toBe("80/tcp http · Apache httpd · 2.4.52");
  expect(nodeSummary({ type: "technique", status: "attempt-failed", label: "whatweb",
    meta: JSON.stringify({ error: "timeout", exitCode: 124 }) }))
    .toBe("timeout · exit 124");
  expect(nodeStatusReason({ type: "technique", status: "in-progress",
    meta: JSON.stringify({ executionStatus: "completed" }) })).toBe("사용자 검토 대기");
  expect(nodeStatusReason({ type: "service", status: "blocked", meta: "{}" }))
    .toBe("선행 정보 부족");
});

it("builds a newest-first clickable activity feed from graph nodes", () => {
  const nodes = [{ id: "svc", type: "service", status: "untried", label: "80/tcp http",
    objective: false, source_ref: "", hidden: false, created_at: "2026-08-09T10:42:38Z",
    meta: JSON.stringify({ product: "Apache", version: "2.4.52" }) },
  { id: "cred", type: "credential", status: "succeeded", label: "Administrator",
    objective: false, source_ref: "", hidden: false, created_at: "2026-08-09T10:46:09Z",
    meta: JSON.stringify({ username: "Administrator", credType: "NetNTLMv2" }) }];
  const feed = buildActivityFeed({ root_node_id: null,
    nodes: nodes as Parameters<typeof buildActivityFeed>[0]["nodes"], edges: [] });
  expect(feed.map((item) => item.nodeId)).toEqual(["cred", "svc"]);
  expect(feed[0].text).toContain("captured");
  expect(filterActivityFeed(feed, "apache", "service").map((item) => item.nodeId))
    .toEqual(["svc"]);
  expect(filterActivityFeed(feed, "administrator", "finding")).toEqual([]);
});

it("keeps a moved or resized activity stream inside the graph", () => {
  expect(clampActivityPanel(900, -20, 280, 180, 1000, 700))
    .toEqual({ x: 692, y: 0 });
});

it("inserts the tun0 responder path without leaving the graph request panel", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify({
    tun0: "tun0 UNKNOWN 10.10.16.178/23",
  }), { headers: { "Content-Type": "application/json" } }))));
  location.hash = "#graph";
  render(<GraphRequestPanel draft={{ projectId: 3, targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=french.html" }} onBack={vi.fn()} />);

  fireEvent.click(await screen.findByText("RESPONDER IP · 10.10.16.178"));
  expect((screen.getByLabelText("Request URL") as HTMLInputElement).value)
    .toBe("http://unika.htb/index.php?page=\\\\10.10.16.178\\test");
  expect(location.hash).toBe("#graph");
});

it("offers the full link-extract workflow from an execution node", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/executions/42/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "css/style.css\nhttps://cdn.example/app.js\n/index.php?page=german.html\n",
      stderr: "", status: "completed", error: "", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      { id: 10, project_id: 3, ip: "10.10.11.80", hostname: "unika.htb" },
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

  const openRequest = vi.fn();
  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10, serviceId: 20 }} node={{
      id: "tech-1", type: "technique", status: "succeeded",
      label: "http-link-extract", objective: false, hidden: false,
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 42 }),
    }} busy={false} onOpenRequest={openRequest}
      onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  await screen.findByText("/index.php?page=german.html");
  const result = screen.getByLabelText("링크 추출 결과");
  expect(result.textContent?.indexOf("/index.php?page=german.html"))
    .toBeLessThan(result.textContent?.indexOf("https://cdn.example/app.js") ?? 0);
  expect(result.textContent?.indexOf("https://cdn.example/app.js"))
    .toBeLessThan(result.textContent?.indexOf("css/style.css") ?? 0);

  const requestButtons = screen.getAllByText("Request 탭에 채우기");
  expect(requestButtons).toHaveLength(2);
  location.hash = "#graph";
  fireEvent.click(requestButtons[0]);
  expect(JSON.parse(localStorage.getItem("oscp-web-launch") || "null")).toEqual({
    targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=german.html",
  });
  expect(location.hash).toBe("#graph");
  expect(openRequest).toHaveBeenCalledWith({ projectId: 3, targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=german.html" });

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

it("shows captured credentials for a responder session node", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    const body = url.endsWith("/api/targets") ? [
      { id: 10, project_id: 3, ip: "10.129.95.234" },
    ] : url.endsWith("/api/targets/10/responder-captures") ? [{
      label: "SMB-NTLMv2-SSP", username: "Administrator",
      value: "Administrator::RESPONDER:challenge:response", cleartext: false,
      captured_at: "2026-08-09T14:00:00Z",
    }] : null;
    if (body === null) throw new Error(`Unhandled request: ${url}`);
    return Promise.resolve(new Response(JSON.stringify(body), {
      headers: { "Content-Type": "application/json" },
    }));
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10 }} node={{
      id: "session-1", type: "technique", status: "in-progress",
      label: "responder-listener", objective: false, hidden: false,
      source_ref: JSON.stringify({ module: "sessions", kind: "session", id: 9 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("Administrator")).toBeTruthy();
  expect(screen.getByText("NETNTLMv2")).toBeTruthy();
  expect(screen.getByText("해시 보기")).toBeTruthy();
  expect(screen.getByText("Credential 저장")).toBeTruthy();
});
