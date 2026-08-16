// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {afterEach, expect, it, vi} from "vitest";
import AutoReconPanel from "./AutoReconPanel";
import type {Target} from "./scanCenterModel";

afterEach(cleanup);

const targets: Target[] = [
  {id: 1, project_id: 10, name: "DC01", ip: "10.10.10.10"},
  {id: 2, project_id: 10, name: "", ip: "10.10.10.11"},
];

function renderPanel(overrides: Partial<Parameters<typeof AutoReconPanel>[0]> = {}) {
  const client = new QueryClient({defaultOptions: {queries: {retry: false}}});
  const props = {
    targets, selectedIds: new Set<number>(), onToggle: vi.fn(), onSelectAll: vi.fn(),
    onClear: vi.fn(), onStart: vi.fn(), starting: false, onOpenJob: vi.fn(),
    ...overrides,
  };
  render(<QueryClientProvider client={client}><AutoReconPanel {...props} /></QueryClientProvider>);
  return props;
}

it("lists every target in the project as a checkbox and toggles selection on click", () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(
    new Response(JSON.stringify([]), {headers: {"Content-Type": "application/json"}}))));
  const props = renderPanel();
  expect(screen.getByText("DC01")).toBeTruthy();
  expect(screen.getByText("10.10.10.11")).toBeTruthy();
  fireEvent.click(screen.getAllByRole("checkbox")[0]);
  expect(props.onToggle).toHaveBeenCalledWith(1);
});

it("keeps the start button disabled until scope is acknowledged and a target is selected", () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(
    new Response(JSON.stringify([]), {headers: {"Content-Type": "application/json"}}))));
  const props = renderPanel({selectedIds: new Set([1])});
  const start = screen.getByText(/AutoRecon 시작/);
  expect(start.closest("button")!.disabled).toBe(true);

  fireEvent.click(screen.getByText(/SCOPE ACKNOWLEDGEMENT/).closest("label")!
    .querySelector("input")!);
  expect(start.closest("button")!.disabled).toBe(false);

  fireEvent.click(start);
  expect(props.onStart).toHaveBeenCalled();
});

it("shows a target as idle when it has no autorecon-tagged scan yet", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(
    new Response(JSON.stringify([]), {headers: {"Content-Type": "application/json"}}))));
  renderPanel({selectedIds: new Set([1])});
  expect(await screen.findByText("대기 · 아직 시작되지 않음")).toBeTruthy();
});

it("shows the running scan's status and per-service execution counts, and opens it on click", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/scans?target_id=1")) return Promise.resolve(
      new Response(JSON.stringify([
        {id: 71, source: "executed", status: "running", command: "nmap -p- 10.10.10.10",
         created_at: "2026-08-16T00:00:00Z", error: "", alias: "", tags: "[\"autorecon\"]"},
      ]), {headers: {"Content-Type": "application/json"}}));
    if (url.endsWith("/api/scans/71/service-executions")) return Promise.resolve(
      new Response(JSON.stringify([
        {id: 1, status: "completed", template_id: "http-whatweb"},
        {id: 2, status: "running", template_id: "http-nikto"},
        {id: 3, status: "failed", template_id: "smb-enum4linux"},
      ]), {headers: {"Content-Type": "application/json"}}));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const props = renderPanel({selectedIds: new Set([1])});

  expect(await screen.findByText(/서비스 명령 3개/)).toBeTruthy();
  expect(screen.getByText(/완료 1 · 진행중 1 · 실패 1/)).toBeTruthy();

  fireEvent.click(document.querySelector(".autoReconJobRow")!);
  expect(props.onOpenJob).toHaveBeenCalledWith(1, 71);
});
