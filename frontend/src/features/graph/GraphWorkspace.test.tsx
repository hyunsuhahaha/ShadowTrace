// @vitest-environment jsdom
import React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { Inspector } from "./GraphWorkspace";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("shows links produced by a link-extract execution node", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify({
    stdout: "/index.php?page=german.html\ncss/style.css\n",
    stderr: "", status: "completed", error: "", exit_code: 0,
  }), { headers: { "Content-Type": "application/json" } }))));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "tech-1", type: "technique", status: "succeeded",
      label: "http-link-extract", objective: false, hidden: false,
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 42 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("/index.php?page=german.html")).toBeTruthy();
  expect(screen.getByText("css/style.css")).toBeTruthy();
});
