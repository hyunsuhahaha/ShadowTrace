// @vitest-environment jsdom
import {afterEach, expect, test, vi} from "vitest";
import {DEFAULT_TERMINAL_FONT_SIZE, readTerminalFontSize, setTerminalFontSize,
  TERMINAL_FONT_EVENT, TERMINAL_FONT_KEY} from "./terminalFont";

afterEach(() => localStorage.clear());

test("저장값이 없으면 읽기 쉬운 기본 크기를 사용한다", () => {
  expect(readTerminalFontSize()).toBe(DEFAULT_TERMINAL_FONT_SIZE);
});

test("터미널 글자 크기를 저장하고 허용 범위로 제한해 알린다", () => {
  const listener = vi.fn();
  addEventListener(TERMINAL_FONT_EVENT, listener);

  expect(setTerminalFontSize(40)).toBe(24);
  expect(localStorage.getItem(TERMINAL_FONT_KEY)).toBe("24");
  expect((listener.mock.calls[0][0] as CustomEvent<number>).detail).toBe(24);
  expect(setTerminalFontSize(5)).toBe(12);

  removeEventListener(TERMINAL_FONT_EVENT, listener);
});
