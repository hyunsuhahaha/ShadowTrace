export const TERMINAL_FONT_KEY = "oscp-terminal-font-size";
export const TERMINAL_FONT_EVENT = "oscp-terminal-font-size-change";
export const DEFAULT_TERMINAL_FONT_SIZE = 16;

export function readTerminalFontSize(): number {
  const saved = Number(localStorage.getItem(TERMINAL_FONT_KEY));
  return Number.isFinite(saved) && saved >= 12 && saved <= 24
    ? saved : DEFAULT_TERMINAL_FONT_SIZE;
}

export function setTerminalFontSize(size: number): number {
  const next = Math.max(12, Math.min(24, size));
  localStorage.setItem(TERMINAL_FONT_KEY, String(next));
  dispatchEvent(new CustomEvent(TERMINAL_FONT_EVENT, {detail: next}));
  return next;
}
