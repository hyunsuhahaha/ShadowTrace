// @vitest-environment jsdom
import React from "react";
import {cleanup, fireEvent, render, screen, waitFor} from "@testing-library/react";
import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {afterEach, expect, it, vi} from "vitest";
import AppShell from "./AppShell";

const response = (body: unknown) => Promise.resolve(new Response(
  JSON.stringify(body), {headers: {"Content-Type": "application/json"}},
));

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});

it("updates the shell when the active project changes", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/projects")) return response([
      {id: 1, name: "Alpha"},
      {id: 2, name: "Bravo"},
    ]);
    if (url.endsWith("/api/targets")) return response([
      {id: 10, project_id: 1, name: "alpha-host", ip: "10.0.0.1"},
      {id: 20, project_id: 2, name: "bravo-host", ip: "10.0.0.2"},
    ]);
    if (url.endsWith("/api/vpn/status")) return response({
      connected: false, tun0: "", operation: null,
    });
    throw new Error(`Unhandled request: ${url}`);
  }));
  localStorage.setItem("oscp-workspace-project", "1");
  const client = new QueryClient({
    defaultOptions: {queries: {retry: false, staleTime: Infinity}},
  });
  const {container} = render(
    <QueryClientProvider client={client}>
      <AppShell route="enumeration"><div /></AppShell>
    </QueryClientProvider>,
  );

  await screen.findByText("Alpha");
  fireEvent.change(screen.getByRole("combobox", {name: "현재 프로젝트"}), {
    target: {value: "2"},
  });

  await waitFor(() => expect(screen.getByText("Bravo")).toBeTruthy());
  expect(screen.getByText("bravo-host · 10.0.0.2")).toBeTruthy();
  expect(localStorage.getItem("oscp-workspace-project")).toBe("2");

  fireEvent.click(screen.getByRole("button", {name: "전체 메뉴 접기"}));
  expect(container.querySelector(".appShell")?.classList.contains(
    "appShell--sidebarCollapsed")).toBe(true);
  expect(localStorage.getItem("oscp-sidebar-collapsed")).toBe("true");

  fireEvent.click(screen.getByRole("button", {name: "전체 메뉴 펼치기"}));
  const separator = screen.getByRole("separator", {name: "전체 메뉴 너비 조절"});
  fireEvent.wheel(separator, {deltaY: -100});
  expect(localStorage.getItem("oscp-sidebar-width")).toBe("280");
});
