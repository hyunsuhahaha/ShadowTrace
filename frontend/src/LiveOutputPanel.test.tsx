// @vitest-environment jsdom
import {render, screen} from "@testing-library/react";
import {expect, it} from "vitest";
import LiveOutputPanel from "./LiveOutputPanel";

it("shows the idle state without a focused run", () => {
  render(<LiveOutputPanel elapsed={0} outcome={null} output="" />);
  expect(screen.getByText("명령 실행 대기")).toBeTruthy();
});

it("reports focused run status, error message and outcome", () => {
  render(<LiveOutputPanel
    run={{templateId: "nmap", name: "Nmap", status: "failed", startedAt: 0,
      lastEventAt: 0, message: "연결 시간 초과", exitCode: 1}}
    elapsed={12} outcome={{tone: "danger", title: "조사가 완료되지 않았습니다",
      detail: "오류 출력을 확인하세요."}}
    output="$ nmap -sV 10.10.10.10\n" />);
  expect(screen.getByText(/Nmap ·/)).toBeTruthy();
  expect(screen.getByText(/종료 코드 1/)).toBeTruthy();
  expect(screen.getByText("연결 시간 초과")).toBeTruthy();
  expect(screen.getByText("조사가 완료되지 않았습니다")).toBeTruthy();
  expect(screen.getByText(/nmap -sV 10.10.10.10/)).toBeTruthy();
});
