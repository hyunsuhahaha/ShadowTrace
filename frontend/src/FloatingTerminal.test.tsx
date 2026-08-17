// @vitest-environment jsdom
import {useEffect, type ReactNode} from "react";
import {cleanup, fireEvent, render, screen, within} from "@testing-library/react";
import {afterEach, beforeEach, expect, test, vi} from "vitest";
import {DetachableTerminal, FloatingTerminalProvider, useFloatingTerminal} from "./FloatingTerminal";

class EventSourceStub {
  onopen = null;
  onmessage = null;
  onerror = null;
  close = vi.fn();
}

beforeEach(() => {
  vi.stubGlobal("matchMedia", vi.fn(() => ({
    matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn(),
    addListener: vi.fn(), removeListener: vi.fn(),
  })));
  vi.stubGlobal("ResizeObserver", class {
    observe() {} disconnect() {}
  });
});

function DetachFromGraph() {
  const {floatScan} = useFloatingTerminal();
  return <button onClick={() => floatScan({
    scanId: 31, projectId: 1, targetId: 3, targetIp: "10.129.255.39", command: "nmap",
    source: "nmap", status: "completed", linkType: "tun0", initialOutput: "",
  }, new DOMRect(40, 60, 680, 420))}>분리</button>;
}

function DetachAutoReconRun() {
  const {floatScan} = useFloatingTerminal();
  return <button onClick={() => floatScan({
    scanId: 7, projectId: 1, targetId: 3, targetIp: "10.129.255.39, 10.129.255.40",
    command: "autorecon 10.129.255.39 10.129.255.40", source: "autorecon",
    status: "running", linkType: "local", initialOutput: "", endpoint: "autorecon",
  }, new DOMRect(40, 60, 680, 420))}>autorecon 분리</button>;
}

function GraphExecutionTerminal() {
  return <DetachableTerminal id="graph-execution-42" label="그래프 실행 결과">
    <section aria-label="실행 결과">
      <header data-terminal-drag-handle>10.10.10.55:22 — 제품·버전 식별</header>
      <pre>OpenSSH 8.0p1</pre>
    </section>
  </DetachableTerminal>;
}

function OpenTwoTerminals() {
  const {floatTerminal} = useFloatingTerminal();
  return <>
    <button onClick={() => floatTerminal({id: "pty-1", label: "Responder",
      content: <div>responder output</div>}, new DOMRect(40, 60, 600, 360))}>첫 번째</button>
    <button onClick={() => floatTerminal({id: "pty-2", label: "evil-winrm",
      content: <div>winrm output</div>}, new DOMRect(80, 90, 600, 360))}>두 번째</button>
  </>;
}

function MountSpy({onMount, children}: {onMount: () => void; children: ReactNode}) {
  useEffect(() => { onMount(); }, []);
  return <>{children}</>;
}

function OpenTwoTerminalsWithMountSpies({onMount}: {onMount: (id: string) => void}) {
  const {floatTerminal} = useFloatingTerminal();
  return <>
    <button onClick={() => floatTerminal({id: "pty-1", label: "Responder",
      content: <MountSpy onMount={() => onMount("pty-1")}><div>responder output</div></MountSpy>},
      new DOMRect(40, 60, 600, 360))}>첫 번째</button>
    <button onClick={() => floatTerminal({id: "pty-2", label: "evil-winrm",
      content: <MountSpy onMount={() => onMount("pty-2")}><div>winrm output</div></MountSpy>},
      new DOMRect(80, 90, 600, 360))}>두 번째</button>
  </>;
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

test("스캔 터미널에서 모든 xterm의 글자 크기를 조절한다", () => {
  vi.stubGlobal("EventSource", EventSourceStub);
  render(<FloatingTerminalProvider><DetachFromGraph /></FloatingTerminalProvider>);

  fireEvent.click(screen.getByRole("button", {name: "분리"}));
  fireEvent.click(screen.getByRole("button", {name: "터미널 글자 확대"}));

  expect(localStorage.getItem("oscp-terminal-font-size")).toBe("17");
  expect(screen.getByLabelText("터미널 글자 크기").textContent).toContain("17");
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

test("endpoint가 autorecon이면 /api/scans가 아니라 /api/autorecon 이벤트 스트림을 구독한다", () => {
  class RecordingEventSource {
    static urls: string[] = [];
    onopen = null; onmessage = null; onerror = null;
    constructor(url: string) { RecordingEventSource.urls.push(url); }
    close = vi.fn();
  }
  vi.stubGlobal("EventSource", RecordingEventSource);
  render(<FloatingTerminalProvider><DetachAutoReconRun /></FloatingTerminalProvider>);

  fireEvent.click(screen.getByRole("button", {name: "autorecon 분리"}));

  expect(RecordingEventSource.urls).toEqual(["/api/autorecon/7/events"]);
  const terminal = screen.getByLabelText("플로팅 스캔 터미널 #7");
  expect(terminal.querySelector(".floatingTerminal__bar")?.textContent)
    .toContain("autorecon://10.129.255.39, 10.129.255.40/run/7");
});

test("여러 xterm 창을 동시에 유지하고 각각 닫는다", () => {
  render(<FloatingTerminalProvider><OpenTwoTerminals /></FloatingTerminalProvider>);
  fireEvent.click(screen.getByText("첫 번째"));
  fireEvent.click(screen.getByText("두 번째"));

  const responder = screen.getByLabelText("플로팅 터미널 Responder");
  expect(responder).toBeTruthy();
  expect(screen.getByLabelText("플로팅 터미널 evil-winrm")).toBeTruthy();
  fireEvent.click(within(responder).getByText("[ 원위치 ]"));
  expect(screen.queryByLabelText("플로팅 터미널 Responder")).toBeNull();
  expect(screen.getByLabelText("플로팅 터미널 evil-winrm")).toBeTruthy();
});

test("두 번째 터미널을 띄워도 첫 번째 터미널의 PTY 컴포넌트가 재마운트되지 않는다", () => {
  const mounts: string[] = [];
  render(<FloatingTerminalProvider>
    <OpenTwoTerminalsWithMountSpies onMount={(id) => mounts.push(id)} />
  </FloatingTerminalProvider>);

  fireEvent.click(screen.getByText("첫 번째"));
  expect(mounts).toEqual(["pty-1"]);

  fireEvent.click(screen.getByText("두 번째"));
  // A remount here would close pty-1's real WebSocket, which the backend
  // reads as the operator hanging up and SIGTERMs a still-running listener
  // like Responder -- exactly the bug this list-based layout fixes.
  expect(mounts).toEqual(["pty-1", "pty-2"]);
});
