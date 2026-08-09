// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import ScanProfileComposer from "./ScanProfileComposer";
import type {Profile} from "./scanCenterModel";

afterEach(cleanup);

const profiles: Profile[] = [
  {
    id: 1, name: "선택 포트 상세 스캔", kind: "selected_ports",
    description: "", arguments: "-sC -sV -p {ports}", engine: "nmap", chain_kind: "",
  },
  {
    id: 2, name: "전체 TCP 빠른 탐색 (sudo)", kind: "full_tcp_syn",
    description: "", arguments: "-Pn -p- --min-rate 1000 -T4", engine: "nmap",
    chain_kind: "",
  },
];

const baseProps = {
  tool: "nmap" as const,
  targetIp: "", targetName: "", targetError: "",
  onTargetIpChange: vi.fn(), onTargetNameChange: vi.fn(),
  profiles, profileId: 2, onSelectProfile: vi.fn(),
  profile: profiles[1], target: {id: 1, project_id: 1, name: "target", ip: "10.10.10.10"},
  ports: "80,443", topPorts: "100",
  onPortsChange: vi.fn(), onTopPortsChange: vi.fn(), onUpload: vi.fn(),
  previewCommand: "sudo nmap -Pn -p- --min-rate 1000 -T4 10.10.10.10",
  canReview: true, onReviewScan: vi.fn(),
};

it("marks a privileged profile's preview with sudo and reports its Korean label", () => {
  render(<ScanProfileComposer {...baseProps} />);
  expect(screen.getAllByText("전체 TCP 빠른 탐색 (sudo)").length).toBe(2);
  expect(screen.getAllByText(/sudo nmap -Pn -p- --min-rate 1000 -T4 10\.10\.10\.10/).length)
    .toBe(2);
});

it("disables review until an IP and profile make it reviewable, then runs the scan directly", () => {
  const onReviewScan = vi.fn();
  render(<ScanProfileComposer {...baseProps} canReview={false}
    onReviewScan={onReviewScan} targetIp="10.10.10.20" />);
  expect(screen.getByText(/새 Nmap 스캔 검토/).closest("button")!.hasAttribute("disabled"))
    .toBe(true);

  render(<ScanProfileComposer {...baseProps} canReview
    onReviewScan={onReviewScan} targetIp="10.10.10.20" />);
  fireEvent.click(screen.getAllByText(/새 Nmap 스캔 검토/)[1]);
  expect(onReviewScan).toHaveBeenCalledOnce();
});
