// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import ScanJobStatus from "./ScanJobStatus";
import type {Scan} from "./scanCenterModel";

afterEach(cleanup);

const scan: Scan = {
  id: 5, source: "executed", status: "running", command: "nmap -Pn 10.10.10.10",
  created_at: "2026-08-02T00:00:00Z", started_at: "2026-08-02T00:00:00Z",
  error: "", alias: "", tags: "[]",
};

it("warns when a running scan has gone quiet for over 30 seconds", () => {
  render(<ScanJobStatus selected={scan} clock={40000} streamState="connected"
    lastEventAt={1000} openTcpPorts={[]}
    onOpenChainedScan={vi.fn()} onUseDiscoveredPorts={vi.fn()} />);
  expect(screen.getByRole("alert")).toBeTruthy();
});

it("offers a shortcut into a masscan discovery's open ports", () => {
  const onUseDiscoveredPorts = vi.fn();
  render(<ScanJobStatus
    selected={{...scan, status: "completed"}} clock={2000} streamState="idle"
    selectedProfile={{id: 1, name: "masscan", kind: "masscan_discovery", description: "",
      arguments: "", engine: "masscan", chain_kind: ""}}
    openTcpPorts={[22, 80, 445]}
    onOpenChainedScan={vi.fn()} onUseDiscoveredPorts={onUseDiscoveredPorts} />);
  expect(screen.getByText("열린 포트 3개 발견")).toBeTruthy();
  fireEvent.click(screen.getByText("발견된 포트로 상세 스캔 준비"));
  expect(onUseDiscoveredPorts).toHaveBeenCalledOnce();
});

it("opens an auto-chained follow-up scan", () => {
  const onOpenChainedScan = vi.fn();
  render(<ScanJobStatus
    selected={{...scan, status: "completed"}} clock={2000} streamState="idle"
    chainedScan={{...scan, id: 9, status: "running"}} openTcpPorts={[]}
    onOpenChainedScan={onOpenChainedScan} onUseDiscoveredPorts={vi.fn()} />);
  fireEvent.click(screen.getByText("상세 스캔 열기"));
  expect(onOpenChainedScan).toHaveBeenCalledWith(9);
});
