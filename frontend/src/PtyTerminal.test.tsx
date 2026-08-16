// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import PtyTerminal from "./PtyTerminal";

// xterm.js needs real canvas rendering this jsdom environment doesn't have --
// every other test in this codebase that touches a terminal mocks it out the
// same way (see InteractiveTerminal.test.tsx). This test is about the
// WebSocket reconnect state machine, not terminal rendering, so a minimal
// fake that records what was written is enough to assert against.
const written: string[] = [];
vi.mock("@xterm/xterm", () => ({
  Terminal: class {
    cols = 80; rows = 24;
    options: Record<string, unknown> = {};
    write(data: unknown) { written.push(String(data)); }
    writeln(data: unknown) { written.push(String(data)); }
    open() {}
    loadAddon() {}
    onData() { return { dispose() {} }; }
    focus() {}
    refresh() {}
    dispose() {}
  },
}));
vi.mock("@xterm/addon-fit", () => ({
  FitAddon: class { fit() {} },
}));

class FakeWebSocket {
  static OPEN = 1;
  static instances: FakeWebSocket[] = [];
  url: string;
  binaryType = "";
  readyState = 0;
  onopen: (() => void) | null = null;
  onclose: ((event: { code: number }) => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }
  send() {}
  close() {}
  open() {
    this.readyState = FakeWebSocket.OPEN;
    this.onopen?.();
  }
  remoteClose(code: number) {
    this.readyState = 3;
    this.onclose?.({ code });
  }
}

beforeEach(() => {
  written.length = 0;
  FakeWebSocket.instances = [];
  Element.prototype.scrollIntoView = vi.fn();
  vi.stubGlobal("WebSocket", FakeWebSocket);
  vi.stubGlobal("ResizeObserver", class {
    observe() {} disconnect() {}
  });
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response("{}"))));
  Object.defineProperty(document, "fonts", {
    value: { ready: Promise.resolve() }, configurable: true,
  });
  vi.useFakeTimers();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

async function flushMicrotasks() {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
}

it("reconnects with backoff after an unexpected drop instead of leaving the operator stuck on 종료됨", async () => {
  render(<PtyTerminal sessionId={7} onClose={vi.fn()} />);
  await flushMicrotasks();
  expect(FakeWebSocket.instances).toHaveLength(1);
  FakeWebSocket.instances[0].open();

  // A code the backend never sends deliberately for this session (e.g. 1006,
  // a raw network-level drop) with the underlying process still alive.
  FakeWebSocket.instances[0].remoteClose(1006);
  expect(written.some((line) => line.includes("재연결 시도 중"))).toBe(true);
  expect(FakeWebSocket.instances).toHaveLength(1);

  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  expect(FakeWebSocket.instances).toHaveLength(2);
});

it("does not reconnect once the backend reports the session is truly gone (4409)", async () => {
  render(<PtyTerminal sessionId={8} onClose={vi.fn()} />);
  await flushMicrotasks();
  FakeWebSocket.instances[0].open();

  FakeWebSocket.instances[0].remoteClose(4409);
  expect(written.some((line) => line.includes("다시 시작해야 합니다"))).toBe(true);

  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(FakeWebSocket.instances).toHaveLength(1);
});

it("does not reconnect after the operator's own 연결 종료 click", async () => {
  render(<PtyTerminal sessionId={9} onClose={vi.fn()} />);
  await flushMicrotasks();
  FakeWebSocket.instances[0].open();
  await flushMicrotasks();

  fireEvent.click(screen.getByText("연결 종료"));
  // Fake timers break testing-library's own findBy/waitFor polling, so this
  // relies on the confirm-armed label appearing synchronously off the same
  // click's state update instead of an async query.
  expect(screen.getByText("정말 종료? (다시 클릭)")).toBeTruthy();
  fireEvent.click(screen.getByText("정말 종료? (다시 클릭)"));
  await flushMicrotasks();

  FakeWebSocket.instances[0].remoteClose(1000);
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(FakeWebSocket.instances).toHaveLength(1);
});
