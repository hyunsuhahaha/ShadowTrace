// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import ScanHistoryPanel from "./ScanHistoryPanel";
import type {Scan} from "./scanCenterModel";

afterEach(cleanup);

const scan: Scan = {
  id: 5, source: "executed", status: "running", command: "nmap -Pn 10.10.10.10",
  created_at: "2026-08-02T00:00:00Z", error: "", alias: "", tags: "[]",
};

it("lets a queued scan be cancelled and a completed one be rerun", () => {
  const onStop = vi.fn();
  const onRerun = vi.fn();
  render(<ScanHistoryPanel
    visibleScans={[scan, {...scan, id: 6, status: "completed"}]}
    isLoading={false} error={undefined}
    query="" statusFilter="all"
    onQueryChange={vi.fn()} onStatusFilterChange={vi.fn()}
    onSelectScan={vi.fn()} onStop={onStop} onRerun={onRerun}
    onSelectBase={vi.fn()} />);

  fireEvent.click(screen.getByText("취소"));
  expect(onStop).toHaveBeenCalledWith(5);
  fireEvent.click(screen.getByText("재실행"));
  expect(onRerun).toHaveBeenCalledWith(6);
});

it("shows the diff summary against a chosen baseline scan", () => {
  render(<ScanHistoryPanel
    visibleScans={[scan]} allScans={[scan, {...scan, id: 6}]}
    scanId={5} isLoading={false} error={undefined}
    query="" statusFilter="all"
    onQueryChange={vi.fn()} onStatusFilterChange={vi.fn()}
    onSelectScan={vi.fn()} onStop={vi.fn()} onRerun={vi.fn()}
    baseId={6} onSelectBase={vi.fn()}
    diff={{
      added: [{protocol: "tcp", port: 443, name: "https", product: "", version: ""}],
      removed: [], changed: [],
    }} />);
  expect(screen.getByText("+1")).toBeTruthy();
  expect(screen.getByText("추가 443/tcp")).toBeTruthy();
});

it("shows the empty state when no scans match the filters", () => {
  render(<ScanHistoryPanel
    visibleScans={[]} isLoading={false} error={undefined}
    query="" statusFilter="all"
    onQueryChange={vi.fn()} onStatusFilterChange={vi.fn()}
    onSelectScan={vi.fn()} onStop={vi.fn()} onRerun={vi.fn()}
    onSelectBase={vi.fn()} />);
  expect(screen.getByText("조건에 맞는 스캔이 없습니다.")).toBeTruthy();
});
