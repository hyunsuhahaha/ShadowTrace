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
  targetIp: "", targetError: "",
  onTargetIpChange: vi.fn(),
  profiles, profileId: 2, onSelectProfile: vi.fn(),
  profile: profiles[1],
  ports: "80,443", topPorts: "100",
  onPortsChange: vi.fn(), onTopPortsChange: vi.fn(), onUpload: vi.fn(),
  previewCommand: "sudo nmap -Pn -p- --min-rate 1000 -T4 10.10.10.10",
  canReview: true, onReviewScan: vi.fn(),
  vpnConnected: true, vpnAddress: "tun0 10.10.14.2/24", scopeConfirmed: false,
};

it("marks a privileged profile's preview with sudo and reports its Korean label", () => {
  render(<ScanProfileComposer {...baseProps} />);
  expect(screen.getByText("전체 TCP 빠른 탐색 (sudo)")).toBeTruthy();
  expect(screen.getByText(/sudo nmap -Pn -p- --min-rate 1000 -T4 10\.10\.10\.10/)).toBeTruthy();
});

it("disables run until an IP and profile make it reviewable, then opens scope review", () => {
  const onReviewScan = vi.fn();
  render(<ScanProfileComposer {...baseProps} canReview={false}
    onReviewScan={onReviewScan} targetIp="10.10.10.20" />);
  expect(screen.getByText(/RUN/).closest("button")!.hasAttribute("disabled"))
    .toBe(true);

  render(<ScanProfileComposer {...baseProps} canReview
    onReviewScan={onReviewScan} targetIp="10.10.10.20" />);
  fireEvent.click(screen.getAllByText(/RUN/)[1]);
  expect(onReviewScan).toHaveBeenCalledOnce();
});

it("shows command provenance and blocks an engine or target context drift", () => {
  const {rerender} = render(<ScanProfileComposer {...baseProps}
    targetIp="10.10.10.10" commandDraft="nmap -Pn 10.10.10.10"
    commandDirty commandContextBound commandEngineBound />);
  expect(screen.getByText("OPERATOR EDIT")).toBeTruthy();
  expect(screen.getByText("SCOPE REVIEW REQUIRED")).toBeTruthy();
  expect(screen.getByText(/RUN/).closest("button")!.hasAttribute("disabled")).toBe(false);

  rerender(<ScanProfileComposer {...baseProps}
    targetIp="10.10.10.10" commandDraft="bash -c id 10.10.10.99"
    commandDirty commandContextBound={false} commandEngineBound={false} />);
  expect(screen.getByText(/TARGET CHANGED/)).toBeTruthy();
  expect(screen.getByText(/ENGINE CHANGED/)).toBeTruthy();
  expect(screen.getByText(/RUN/).closest("button")!.hasAttribute("disabled")).toBe(true);
});

it("allows a new IP to create its target on run without a name or preview", () => {
  render(<ScanProfileComposer {...baseProps} targetIp="10.10.10.99"
    previewCommand={undefined} commandDraft="" canReview />);
  expect(screen.queryByLabelText("대상 이름")).toBeNull();
  expect(screen.queryByText("PROFILE BASE")).toBeNull();
  expect(screen.queryByText(/DRIFT/)).toBeNull();
  expect(screen.getByText(/RUN/).closest("button")!.hasAttribute("disabled")).toBe(false);
});
