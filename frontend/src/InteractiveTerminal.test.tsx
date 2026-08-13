// @vitest-environment jsdom
import {cleanup, render, screen, waitFor} from "@testing-library/react";
import {afterEach, expect, test, vi} from "vitest";
import {FloatingTerminalProvider} from "./FloatingTerminal";
import InteractiveTerminal from "./InteractiveTerminal";

vi.mock("./PtyTerminal", () => ({default: ({sessionId}: {sessionId: number}) =>
  <section>PTY #{sessionId}</section>}));

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
