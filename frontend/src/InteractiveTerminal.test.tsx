// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen, waitFor} from "@testing-library/react";
import {afterEach, expect, test, vi} from "vitest";
import {FloatingTerminalProvider} from "./FloatingTerminal";
import InteractiveTerminal from "./InteractiveTerminal";

let mountCount = 0;
vi.mock("./PtyTerminal", async () => {
  const React = await import("react");
  return {default: ({sessionId, onClose}: {sessionId: number; onClose: () => void}) => {
    React.useEffect(() => { mountCount += 1; }, []);
    return <section>PTY #{sessionId}<button onClick={onClose}>연결 종료</button></section>;
  }};
});

afterEach(() => {
  cleanup();
  localStorage.clear();
});

test("단일 호출 위치에서 새 PTY를 열어도 기존 플로팅 PTY를 유지한다", async () => {
  const view = render(<FloatingTerminalProvider>
    <InteractiveTerminal sessionId={1} title="responder" autoFloat onClose={vi.fn()} />
  </FloatingTerminalProvider>);
  await screen.findByLabelText(/플로팅 터미널 .* #1/);

  view.rerender(<FloatingTerminalProvider>
    <InteractiveTerminal sessionId={2} title="evil-winrm" autoFloat onClose={vi.fn()} />
  </FloatingTerminalProvider>);

  await waitFor(() => {
    expect(screen.getByLabelText(/플로팅 터미널 .* #1/)).toBeTruthy();
    expect(screen.getByLabelText(/플로팅 터미널 .* #2/)).toBeTruthy();
  });
});

test("첫 autoFloat는 PtyTerminal을 인라인으로 먼저 마운트했다가 다시 마운트하지 않는다", async () => {
  mountCount = 0;
  render(<FloatingTerminalProvider>
    <InteractiveTerminal sessionId={7} title="responder" autoFloat onClose={vi.fn()} />
  </FloatingTerminalProvider>);
  await screen.findByLabelText(/플로팅 터미널 .* #7/);

  // A second mount here means the session flashed inline via
  // <DetachableTerminal> for one render before the float effect swapped it
  // out. That inline mount opens a real WebSocket the backend fully
  // accepts and spawns a process for, so unmounting it a moment later
  // reads as the operator hanging up and kills the listener within
  // milliseconds of starting -- before a second terminal is ever opened.
  expect(mountCount).toBe(1);
});

test("autoFloat 터미널은 원위치를 눌러도 세션이 끊기지 않는다", async () => {
  mountCount = 0;
  const onClose = vi.fn();
  render(<FloatingTerminalProvider>
    <InteractiveTerminal sessionId={1} title="evil-winrm" autoFloat onClose={onClose} />
  </FloatingTerminalProvider>);
  await screen.findByLabelText(/플로팅 터미널 .* #1/);
  const mountsAfterFloat = mountCount;

  fireEvent.click(screen.getByRole("button", {name: "[ 원위치 ]"}));

  // Still floating (docking an autoFloat PTY only resets its position),
  // onClose was never called, and no second PtyTerminal mounted trying to
  // reconnect -- the original socket was never touched.
  expect(screen.getByLabelText(/플로팅 터미널 .* #1/)).toBeTruthy();
  expect(onClose).not.toHaveBeenCalled();
  expect(mountCount).toBe(mountsAfterFloat);
});

test("연결 종료 버튼은 여전히 autoFloat 터미널을 실제로 닫는다", async () => {
  const onClose = vi.fn();
  render(<FloatingTerminalProvider>
    <InteractiveTerminal sessionId={1} title="evil-winrm" autoFloat onClose={onClose} />
  </FloatingTerminalProvider>);
  await screen.findByLabelText(/플로팅 터미널 .* #1/);

  fireEvent.click(screen.getByRole("button", {name: "연결 종료"}));

  await waitFor(() => expect(onClose).toHaveBeenCalled());
  expect(screen.queryByLabelText(/플로팅 터미널 .* #1/)).toBeNull();
});
