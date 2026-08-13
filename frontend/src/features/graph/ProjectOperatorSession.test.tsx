// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import ProjectOperatorSession from "./ProjectOperatorSession";

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});

const rootNode = { id: "root", type: "project-root" as const, status: "untried",
  label: "Lab", objective: false, source_ref: "", hidden: false };

it("lets you register the first Target directly from the empty project-root state", async () => {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    if (url.endsWith("/api/vpn/status")) return Promise.resolve(new Response(
      JSON.stringify({ connected: false }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets/ensure") && init?.method === "POST")
      return Promise.resolve(new Response(JSON.stringify(
        { id: 5, project_id: 1, ip: "10.10.10.10", name: "10.10.10.10" }),
        { status: 201, headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  localStorage.setItem("oscp-workspace-project", "1");
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const refreshHandler = vi.fn();
  addEventListener("oscp-graph-refresh", refreshHandler);

  render(<QueryClientProvider client={client}>
    <ProjectOperatorSession project={rootNode} nodes={[]} onSelect={vi.fn()} />
  </QueryClientProvider>);

  fireEvent.change(screen.getByLabelText("Target IP"), { target: { value: "10.10.10.10" } });
  fireEvent.click(screen.getByRole("button", { name: /Target 추가/ }));

  await waitFor(() => expect(refreshHandler).toHaveBeenCalled());
  const ensureCall = calls.find((c) => c.url.endsWith("/api/targets/ensure"));
  expect(JSON.parse(String(ensureCall!.init!.body)))
    .toEqual({ ip: "10.10.10.10", name: "", project_id: 1 });

  removeEventListener("oscp-graph-refresh", refreshHandler);
});

it("does not show the add-target form once at least one Target exists", () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(
    JSON.stringify({ connected: false }), { headers: { "Content-Type": "application/json" } }))));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const target = { id: "host-1", type: "host" as const, status: "untried", label: "10.0.0.5",
    objective: false, hidden: false,
    source_ref: JSON.stringify({ module: "core", kind: "target", id: 9 }) };

  render(<QueryClientProvider client={client}>
    <ProjectOperatorSession project={rootNode} nodes={[target]} onSelect={vi.fn()} />
  </QueryClientProvider>);

  expect(screen.queryByLabelText("Target IP")).toBeNull();
});
