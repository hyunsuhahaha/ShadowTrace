// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, test, vi} from "vitest";
import {DetachableTerminal, FloatingTerminalProvider, useFloatingTerminal} from "./FloatingTerminal";

class EventSourceStub {
  onopen = null;
  onmessage = null;
  onerror = null;
  close = vi.fn();
}

function DetachFromGraph() {
  const {floatScan} = useFloatingTerminal();
  return <button onClick={() => floatScan({
    scanId: 31, projectId: 1, targetId: 3, targetIp: "10.129.255.39", command: "nmap",
    source: "nmap", status: "completed", linkType: "tun0", initialOutput: "",
  }, new DOMRect(40, 60, 680, 420))}>분리</button>;
}

function GraphExecutionTerminal() {
  return <DetachableTerminal id="graph-execution-42" label="그래프 실행 결과">
    <section aria-label="실행 결과">
      <header data-terminal-drag-handle>10.10.10.55:22 — 제품·버전 식별</header>
      <pre>OpenSSH 8.0p1</pre>
    </section>
  </DetachableTerminal>;
}

afterEach(() => {
  cleanup();
  localStorage.clear();
  location.hash = "";
  vi.unstubAllGlobals();
});

test("원위치는 터미널을 분리한 그래프 화면으로 돌아간다", () => {
  vi.stubGlobal("EventSource", EventSourceStub);
  location.hash = "#graph";
  render(<FloatingTerminalProvider><DetachFromGraph /></FloatingTerminalProvider>);

  fireEvent.click(screen.getByRole("button", {name: "분리"}));
  fireEvent.click(screen.getByRole("button", {name: "[ 원위치 ]"}));

  expect(location.hash).toBe("#graph");
});

test("스캔 명령은 잘린 header preview 대신 출력 위에 표시된다", () => {
  vi.stubGlobal("EventSource", EventSourceStub);
  render(<FloatingTerminalProvider><DetachFromGraph /></FloatingTerminalProvider>);

  fireEvent.click(screen.getByRole("button", {name: "분리"}));
  const terminal = screen.getByLabelText("플로팅 스캔 터미널 #31");
  const header = terminal.querySelector(".floatingTerminal__bar");

  expect(header?.textContent).not.toContain("nmap");
  expect(terminal.querySelector(".floatingCommandSession__executed")?.textContent)
    .toContain("nmap");
  expect(screen.getByLabelText("플로팅 터미널 명령")).toBeTruthy();
});

test("크기 조절은 포인터가 grip 밖으로 나가도 계속된다", () => {
  vi.stubGlobal("EventSource", EventSourceStub);
  Object.defineProperties(HTMLElement.prototype, {
    setPointerCapture: {configurable: true, value: vi.fn()},
    hasPointerCapture: {configurable: true, value: () => true},
    releasePointerCapture: {configurable: true, value: vi.fn()},
  });
  render(<FloatingTerminalProvider><DetachFromGraph /></FloatingTerminalProvider>);
  fireEvent.click(screen.getByRole("button", {name: "분리"}));

  const grip = screen.getByRole("separator", {name: "터미널 크기 조절"});
  fireEvent.pointerDown(grip, {button: 0, pointerId: 1, clientX: 720, clientY: 480});
  fireEvent.pointerMove(window, {pointerId: 1, clientX: 840, clientY: 560});
  fireEvent.pointerUp(window, {pointerId: 1, clientX: 840, clientY: 560});

  expect(JSON.parse(localStorage.getItem("oscp-floating-terminal-frame") || "null"))
    .toMatchObject({width: 800, height: 500});
});

test("공용 터미널은 헤더 drag로 전역 floating 된다", () => {
  render(<FloatingTerminalProvider><GraphExecutionTerminal /></FloatingTerminalProvider>);
  const header = screen.getByText("10.10.10.55:22 — 제품·버전 식별");
  fireEvent.pointerDown(header, {button: 0, clientX: 50, clientY: 60});
  fireEvent.pointerMove(window, {clientX: 90, clientY: 100});

  expect(screen.getByLabelText("플로팅 터미널 그래프 실행 결과")).toBeTruthy();
  expect(screen.getByText("OpenSSH 8.0p1")).toBeTruthy();
});
