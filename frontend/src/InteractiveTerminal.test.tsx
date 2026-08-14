// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen, waitFor} from "@testing-library/react";
import {afterEach, expect, test, vi} from "vitest";
import {FloatingTerminalProvider} from "./FloatingTerminal";
import InteractiveTerminal from "./InteractiveTerminal";

let mountCount = 0;
vi.mock("./PtyTerminal", async () => {
  const React = await import("react");
  return {default: ({sessionId}: {sessionId: number}) => {
    React.useEffect(() => { mountCount += 1; }, []);
    return <section>PTY #{sessionId}</section>;
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

test("autoFloat 터미널을 원위치하면 세션에 재연결하지 않고 닫는다", async () => {
  mountCount = 0;
  const onClose = vi.fn();
  render(<FloatingTerminalProvider>
    <InteractiveTerminal sessionId={1} title="evil-winrm" autoFloat onClose={onClose} />
  </FloatingTerminalProvider>);
  await screen.findByLabelText(/플로팅 터미널 .* #1/);
  const mountsAfterFloat = mountCount;

  fireEvent.click(screen.getByRole("button", {name: "[ 원위치 ]"}));

  await waitFor(() => expect(onClose).toHaveBeenCalled());
  expect(screen.queryByLabelText(/플로팅 터미널 .* #1/)).toBeNull();
  // A new PtyTerminal mount here would mean it tried to reconnect to a
  // session the backend already tore down when the first socket closed.
  expect(mountCount).toBe(mountsAfterFloat);
});
