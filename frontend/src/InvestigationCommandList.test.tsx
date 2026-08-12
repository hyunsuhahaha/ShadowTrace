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

it("hides a version prompt once the fact is already known", () => {
  render(<InvestigationCommandList commands={[command]}
    executions={[{id: 1, template_id: command.id, status: "completed"}]}
    target={{hostname: "dc.lab", os_guess: "Windows"} as Target}
    service={{product: "Samba", version: "4.19"} as Service}
    runStates={{}} clock={0} onReview={vi.fn()} />);
  expect(screen.getByText("operation queue 밖의 추가 명령이 없습니다."))
    .toBeTruthy();
});

it("keeps a finished command visible with its result instead of vanishing", () => {
  const probe = {id: "spring-actuator-detect", name: "Actuator 노출 확인",
    description: "인증 없이 노출되는지 확인", preview: "curl -s host/actuator",
    risk: "low", execution_mode: "captured"};
  render(<InvestigationCommandList commands={[probe]}
    executions={[{id: 7, template_id: probe.id, status: "completed", stdout: "{}"}]}
    runStates={{}} clock={0} onReview={vi.fn()} />);
  expect(screen.getByText("Actuator 노출 확인")).toBeTruthy();
  expect(screen.getByText("완료")).toBeTruthy();
  expect(screen.getByText("다시 실행")).toBeTruthy();
  fireEvent.click(screen.getByText("결과 보기"));
  expect(screen.getByText("{}")).toBeTruthy();
});
