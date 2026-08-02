// @vitest-environment jsdom
import {fireEvent, render, screen} from "@testing-library/react";
import {expect, it, vi} from "vitest";
import ServiceDashboard from "./ServiceDashboard";
import type {Service, Target} from "./enumerationModel";

const service = {id: 7, target_id: 2, port: 445, protocol: "tcp", state: "open",
  name: "smb", product: "", version: "", extra_info: "",
  scripts: JSON.stringify([{id: "smb2-time", output: "date: 2026-08-02"}]),
  notes: "", tags: "", cpe: "[]", tls: false, detection_evidence: ""} as Service;
const target = {id: 2, project_id: 1, name: "DC", ip: "10.10.10.10",
  hostname: "", os_guess: "", vpn: "", notes: ""} as Target;
const hostnameCommand = {id: "target-hostname-identity", name: "Hostname 확인",
  risk: "low", execution_mode: "argv"};

it("summarizes missing facts and forwards a target identity check", () => {
  const onReview = vi.fn();
  render(<ServiceDashboard service={service} target={target} commands={[]}
    targetCommands={[hostnameCommand]} executions={[]} runStates={{}}
    clock={0} onReview={onReview} />);
  expect(screen.getByText("5개 미확인")).toBeTruthy();
  expect(screen.getByText("smb2-time")).toBeTruthy();
  fireEvent.click(screen.getAllByText("자동 확인하기")[0]);
  expect(onReview).toHaveBeenCalledWith(hostnameCommand);
});

it("shows an in-progress check without allowing a second run", () => {
  render(<ServiceDashboard service={service} target={target} commands={[]}
    targetCommands={[hostnameCommand]} executions={[]} clock={4000}
    runStates={{[hostnameCommand.id]: {templateId: hostnameCommand.id,
      name: hostnameCommand.name, status: "running", startedAt: 1000}}}
    onReview={vi.fn()} />);
  const button = screen.getByText("3s · 확인 중").closest("button")!;
  expect(button.hasAttribute("disabled")).toBe(true);
});
