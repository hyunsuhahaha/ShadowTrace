// @vitest-environment jsdom
import {fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, test, vi} from "vitest";
import {FloatingTerminalProvider, useFloatingTerminal} from "./FloatingTerminal";

class EventSourceStub {
  onopen = null;
  onmessage = null;
  onerror = null;
  close = vi.fn();
}

function DetachFromGraph() {
  const {floatScan} = useFloatingTerminal();
  return <button onClick={() => floatScan({
    scanId: 31, targetId: 3, targetIp: "10.129.255.39", command: "nmap",
    source: "nmap", status: "completed", linkType: "tun0", initialOutput: "",
  }, new DOMRect(40, 60, 680, 420))}>분리</button>;
}

afterEach(() => {
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
