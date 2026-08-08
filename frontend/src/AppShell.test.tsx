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
    if (url.endsWith("/api/projects/1/services") || url.endsWith("/api/projects/2/services"))
      return response([]);
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

it("feeds the command palette every service in the active project, not just the one on screen", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/projects")) return response([{id: 1, name: "Alpha"}]);
    if (url.endsWith("/api/targets")) return response([
      {id: 10, project_id: 1, name: "web-box", ip: "10.0.0.1"},
      {id: 11, project_id: 1, name: "dc01", ip: "10.0.0.2"},
    ]);
    if (url.endsWith("/api/projects/1/services")) return response([
      {id: 100, target_id: 10, port: 80, protocol: "tcp", name: "http", product: "", scripts: ""},
      {id: 101, target_id: 11, port: 53, protocol: "tcp", name: "domain", product: "", scripts: ""},
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
  render(
    <QueryClientProvider client={client}>
      <AppShell route="enumeration"><div /></AppShell>
    </QueryClientProvider>,
  );
  await screen.findByText("Alpha");

  fireEvent.click(screen.getByRole("button", {name: /검색/}));
  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), {
    target: {value: "gobuster dns"},
  });
  fireEvent.click(screen.getByText("서브도메인 브루트포스 (gobuster dns)"));

  // dc01 is the only project target with a DNS-shaped service — the palette
  // should offer to jump there instead of just failing on the currently
  // selected (unrelated) target.
  await waitFor(() => expect(screen.getByText("dc01 · 10.0.0.2")).toBeTruthy());
});

it("drops every cached query, not just projects/targets, when a project is deleted", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === "DELETE" && url === "/api/projects/1")
      return Promise.resolve(new Response(null, {status: 204}));
    if (url.endsWith("/api/projects")) return response([{id: 1, name: "Alpha"}]);
    if (url.endsWith("/api/targets")) return response([
      {id: 10, project_id: 1, name: "alpha-host", ip: "10.0.0.1"},
    ]);
    if (url.endsWith("/api/projects/1/services")) return response([]);
    if (url.endsWith("/api/vpn/status")) return response({
      connected: false, tun0: "", operation: null,
    });
    throw new Error(`Unhandled request: ${url}`);
  }));
  localStorage.setItem("oscp-workspace-project", "1");
  const client = new QueryClient({
    defaultOptions: {queries: {retry: false, staleTime: Infinity}},
  });
  // Stands in for a workspace tab's cache (e.g. Web Testing's saved
  // requests) that AppShell's delete flow never knew about by name.
  client.setQueryData(["webRequests", 10], [{id: 1, url: "http://stale.example"}]);
  render(
    <QueryClientProvider client={client}>
      <AppShell route="web"><div /></AppShell>
    </QueryClientProvider>,
  );
  await screen.findByText("Alpha");

  fireEvent.click(screen.getByRole("button", {name: "프로젝트 삭제"}));
  fireEvent.click(screen.getByRole("button", {name: "삭제"}));

  await waitFor(() => expect(
    client.getQueryState(["webRequests", 10])?.isInvalidated,
  ).toBe(true));
});
