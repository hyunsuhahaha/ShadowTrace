// @vitest-environment jsdom
import React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import SmbShareResults from "./SmbShareResults";

const response = (body: unknown) => Promise.resolve(new Response(
  JSON.stringify(body), { headers: { "Content-Type": "application/json" } },
));

// jsdom doesn't implement scrollIntoView; every render with shares schedules
// one via rAF, so stub it globally rather than per-test.
HTMLElement.prototype.scrollIntoView ??= () => {};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const shares = [{ name: "WorkShares", type: "Disk", comment: "" }];

it("renders nothing when there are no shares", () => {
  const { container } = render(<SmbShareResults shares={[]} serviceExecutions={[]}
    onSpider={vi.fn()} onViewFile={vi.fn()} onLog={vi.fn()} />);
  expect(container.firstChild).toBeNull();
});

it("connects to a disk share, opens a desktop terminal, and logs the result", async () => {
  const calls: string[] = [];
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push(`${init?.method || "GET"} ${url}`);
    if (url.endsWith("/api/interactive-sessions") && init?.method === "POST")
      return response({ id: 7 });
    if (url.endsWith("/api/interactive-sessions/7/desktop") && init?.method === "POST")
      return response({});
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const onLog = vi.fn();
  render(<SmbShareResults targetId={1} serviceId={2} shares={shares} serviceExecutions={[]}
    onSpider={vi.fn()} onViewFile={vi.fn()} onLog={onLog} />);

  fireEvent.click(screen.getByText("접속"));

  await waitFor(() => expect(onLog).toHaveBeenCalledWith(
    "[Kali 데스크톱 터미널에서 WorkShares 공유에 접속했습니다.]",
  ));
  expect(calls).toEqual([
    "POST /api/interactive-sessions", "POST /api/interactive-sessions/7/desktop",
  ]);
});

it("shows a connect error instead of logging on failure", async () => {
  const fetcher = vi.fn(() => Promise.resolve(
    new Response(JSON.stringify({ detail: "세션을 만들 수 없습니다" }),
      { status: 500, headers: { "Content-Type": "application/json" } }),
  ));
  vi.stubGlobal("fetch", fetcher);
  const onLog = vi.fn();
  render(<SmbShareResults targetId={1} serviceId={2} shares={shares} serviceExecutions={[]}
    onSpider={vi.fn()} onViewFile={vi.fn()} onLog={onLog} />);

  fireEvent.click(screen.getByText("접속"));

  await waitFor(() => expect(screen.getByRole("alert")).toBeTruthy());
  expect(screen.getByRole("alert").textContent).toBe("세션을 만들 수 없습니다");
  expect(onLog).not.toHaveBeenCalled();
});

it("triggers a recursive listing via onSpider without touching the network", () => {
  const onSpider = vi.fn();
  render(<SmbShareResults shares={shares} serviceExecutions={[]}
    onSpider={onSpider} onViewFile={vi.fn()} onLog={vi.fn()} />);

  fireEvent.click(screen.getByText("재귀 목록"));

  expect(onSpider).toHaveBeenCalledWith("WorkShares");
});

it("parses the active spider run's recursive listing and views a file", () => {
  const stdout =
    "  .                                   D        0  Mon Mar 29 04:22:01 2021\n" +
    "  ..                                  D        0  Mon Mar 29 04:22:01 2021\n" +
    "  notes.txt                           A      128  Fri Mar 26 07:00:37 2021\n";
  const onViewFile = vi.fn();
  render(<SmbShareResults shares={shares} activeShare="WorkShares"
    serviceExecutions={[]}
    runState={{ templateId: "smb-share-spider", status: "completed", stdout }}
    onSpider={vi.fn()} onViewFile={onViewFile} onLog={vi.fn()} />);

  expect(screen.getByText("notes.txt")).toBeTruthy();
  fireEvent.click(screen.getByText("원문 보기"));

  expect(onViewFile).toHaveBeenCalledWith("notes.txt");
});

it("disables non-disk shares and prefers the live spider run over history", () => {
  const printShares = [{ name: "PRINT$", type: "Printer", comment: "" }];
  render(<SmbShareResults shares={printShares} serviceExecutions={[]}
    onSpider={vi.fn()} onViewFile={vi.fn()} onLog={vi.fn()} />);

  expect((screen.getByText("접속") as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByText("재귀 목록") as HTMLButtonElement).disabled).toBe(true);
});

it("shows a hint instead of an access column when no nmap scan has run yet", () => {
  render(<SmbShareResults shares={shares} serviceExecutions={[]}
    onSpider={vi.fn()} onViewFile={vi.fn()} onLog={vi.fn()} />);

  expect(screen.getByText(/접근 가능 여부와 무관/)).toBeTruthy();
  expect(screen.queryByText("접근 권한 (nmap)")).toBeNull();
});

it("renders an access badge per share once nmap smb-enum-shares data is available", () => {
  const twoShares = [
    { name: "backups", type: "Disk", comment: "" },
    { name: "ADMIN$", type: "Disk", comment: "Remote Admin" },
  ];
  render(<SmbShareResults shares={twoShares} serviceExecutions={[]}
    shareAccess={{
      backups: { anonymous: "READ", currentUser: "READ/WRITE" },
      "ADMIN$": { anonymous: "<none>", currentUser: "<none>" },
    }}
    onSpider={vi.fn()} onViewFile={vi.fn()} onLog={vi.fn()} />);

  expect(screen.queryByText(/접근 가능 여부와 무관/)).toBeNull();
  expect(screen.getByText("접근 권한 (nmap)")).toBeTruthy();
  expect(screen.getByText("익명: READ")).toBeTruthy();
  expect(screen.getByText("익명: <none>")).toBeTruthy();
});

it("matches share access case-insensitively and flags shares nmap didn't report", () => {
  const twoShares = [
    { name: "Backups", type: "Disk", comment: "" },
    { name: "PRINT$", type: "Printer", comment: "" },
  ];
  render(<SmbShareResults shares={twoShares} serviceExecutions={[]}
    shareAccess={{ backups: { anonymous: "READ", currentUser: "" } }}
    onSpider={vi.fn()} onViewFile={vi.fn()} onLog={vi.fn()} />);

  expect(screen.getByText("익명: READ")).toBeTruthy();
  expect(screen.getByText("확인 안 됨")).toBeTruthy();
});

it("scrolls the results into view when a new share list appears", async () => {
  const scrollIntoView = vi.fn();
  const original = HTMLElement.prototype.scrollIntoView;
  HTMLElement.prototype.scrollIntoView = scrollIntoView;
  try {
    render(<SmbShareResults shares={shares} serviceExecutions={[]}
      onSpider={vi.fn()} onViewFile={vi.fn()} onLog={vi.fn()} />);
    await act(async () => {
      await new Promise((resolve) => requestAnimationFrame(resolve));
    });
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: "smooth", block: "start" });
  } finally {
    HTMLElement.prototype.scrollIntoView = original;
  }
});
