// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import InvestigationCommandList from "./InvestigationCommandList";
import type {Service, Target} from "./enumerationModel";

afterEach(cleanup);

const command = {id: "service-version", name: "버전 탐지", description: "배너 확인",
  preview: "nmap -sV 10.10.10.10", risk: "low", execution_mode: "argv"};

it("shows a remaining command and forwards review", () => {
  const onReview = vi.fn();
  render(<InvestigationCommandList commands={[command]} executions={[]}
    runStates={{}} clock={0} onReview={onReview} />);
  expect(screen.getByText("위험: 낮음")).toBeTruthy();
  fireEvent.click(screen.getByText("검토 후 실행 →"));
  expect(onReview).toHaveBeenCalledWith(command);
});

it("hides a completed command", () => {
  render(<InvestigationCommandList commands={[command]}
    executions={[{template_id: command.id, status: "completed"}]}
    target={{hostname: "dc.lab", os_guess: "Windows"} as Target}
    service={{product: "Samba", version: "4.19"} as Service}
    runStates={{}} clock={0} onReview={vi.fn()} />);
  expect(screen.getByText("이미 확인된 항목을 제외하면 실행할 명령이 없습니다."))
    .toBeTruthy();
});
