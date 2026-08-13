import {useEffect, useRef} from "react";
import {Terminal} from "@xterm/xterm";
import {FitAddon} from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import {readTerminalFontSize, TERMINAL_FONT_EVENT} from "./terminalFont";

export default function XtermOutput({output, cursor = false, ariaLabel = "터미널 출력"}: {
  output: string; cursor?: boolean; ariaLabel?: string;
}) {
  const host = useRef<HTMLDivElement>(null);
  const terminal = useRef<Terminal>();
  const fit = useRef<FitAddon>();

  useEffect(() => {
    if (!host.current) return;
    const instance = new Terminal({
      disableStdin: true, cursorBlink: cursor, cursorStyle: "block",
      convertEol: true, scrollback: 10000,
      fontFamily: '"Liberation Mono", "DejaVu Sans Mono", monospace',
      fontSize: readTerminalFontSize(), lineHeight: 1.2, letterSpacing: 0,
      theme: {background: "#050809", foreground: "#c9d5d8", cursor: "#9fe870",
        selectionBackground: "#31533f"},
    });
    const addon = new FitAddon();
    instance.loadAddon(addon);
    instance.open(host.current);
    terminal.current = instance;
    fit.current = addon;
    const resize = new ResizeObserver(() => requestAnimationFrame(() => addon.fit()));
    resize.observe(host.current);
    addon.fit();
    return () => {
      resize.disconnect();
      terminal.current = undefined;
      fit.current = undefined;
      instance.dispose();
    };
  }, []);

  useEffect(() => {
    const sync = (event: Event) => {
      if (!terminal.current) return;
      terminal.current.options.fontSize = (event as CustomEvent<number>).detail;
      requestAnimationFrame(() => fit.current?.fit());
    };
    addEventListener(TERMINAL_FONT_EVENT, sync);
    return () => removeEventListener(TERMINAL_FONT_EVENT, sync);
  }, []);

  useEffect(() => {
    const instance = terminal.current;
    if (!instance) return;
    instance.reset();
    instance.write(output.replace(/\n/g, "\r\n"));
    instance.scrollToBottom();
  }, [output]);

  useEffect(() => {
    if (terminal.current) terminal.current.options.cursorBlink = cursor;
  }, [cursor]);

  return <div className="xtermOutput" ref={host} role="log" aria-label={ariaLabel} />;
}
