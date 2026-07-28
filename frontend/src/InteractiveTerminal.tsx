import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

export default function InteractiveTerminal({
  sessionId,
  onClose,
}: {
  sessionId: number;
  onClose: () => void;
}) {
  const container = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!container.current) return;
    const terminal = new Terminal({
      cursorBlink: true,
      convertEol: true,
      theme: {
        background: "#050809",
        foreground: "#c9d5d8",
        cursor: "#9fe870",
      },
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(container.current);
    fit.fit();
    const protocol = location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(
      `${protocol}://${location.host}/api/interactive-sessions/${sessionId}/ws`,
    );
    socket.binaryType = "arraybuffer";
    socket.onopen = () => {
      fit.fit();
      socket.send(
        JSON.stringify({
          type: "resize",
          cols: terminal.cols,
          rows: terminal.rows,
        }),
      );
      terminal.focus();
    };
    socket.onmessage = (event) =>
      terminal.write(
        event.data instanceof ArrayBuffer
          ? new Uint8Array(event.data)
          : event.data,
      );
    socket.onclose = () => terminal.write("\r\n[session closed]\r\n");
    const input = terminal.onData((data) => {
      if (socket.readyState === WebSocket.OPEN)
        socket.send(new TextEncoder().encode(data));
    });
    const observer = new ResizeObserver(() => {
      fit.fit();
      if (socket.readyState === WebSocket.OPEN)
        socket.send(
          JSON.stringify({
            type: "resize",
            cols: terminal.cols,
            rows: terminal.rows,
          }),
        );
    });
    observer.observe(container.current);
    return () => {
      observer.disconnect();
      input.dispose();
      socket.close();
      terminal.dispose();
    };
  }, [sessionId]);
  const stop = async () => {
    await fetch(`/api/interactive-sessions/${sessionId}/stop`, {
      method: "POST",
    });
    onClose();
  };
  return (
    <div className="ptyModal">
      <div className="ptyBar">
        <b>INTERACTIVE SESSION #{sessionId}</b>
        <span>Input is not recorded. PTY output is preserved.</span>
        <button onClick={stop}>End session</button>
      </div>
      <div className="ptyTerminal" ref={container} />
    </div>
  );
}
