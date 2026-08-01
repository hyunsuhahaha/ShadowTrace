import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";

export default function InteractiveTerminal({
  sessionId,
  onClose,
  initialInput = "",
  title = "대화형 터미널",
  inputRequest,
}: {
  sessionId: number;
  onClose: () => void;
  initialInput?: string;
  title?: string;
  inputRequest?: { id: number; data: string };
}) {
  const container = useRef<HTMLDivElement>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const targetErrorRef = useRef("");
  const [connection, setConnection] = useState<
    "connecting" | "pty" | "active" | "closed" | "error"
  >("connecting");
  useEffect(() => {
    if (!container.current) return;
    let disposed = false;
    let terminal: Terminal | undefined;
    let observer: ResizeObserver | undefined;
    let input: ReturnType<Terminal["onData"]> | undefined;
    let socket: WebSocket | undefined;
    targetErrorRef.current = "";

    const connect = async () => {
      await document.fonts?.ready;
      if (disposed || !container.current) return;
      terminal = new Terminal({
      cursorBlink: true,
      cursorStyle: "block",
      convertEol: false,
      customGlyphs: true,
      fontFamily: '"Liberation Mono", "DejaVu Sans Mono", monospace',
      fontSize: 14,
      fontWeight: "normal",
      fontWeightBold: "bold",
      letterSpacing: 0,
      lineHeight: 1.15,
      scrollback: 5000,
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
      terminal.writeln("\x1b[90m서버 PTY에 연결하는 중입니다…\x1b[0m");
      const resize = () => {
        requestAnimationFrame(() => {
          if (disposed || !container.current || !terminal) return;
          fit.fit();
          if (socket?.readyState === WebSocket.OPEN)
            socket.send(JSON.stringify({
              type: "resize", cols: terminal.cols, rows: terminal.rows,
            }));
        });
      };
      const protocol = location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(
        `${protocol}://${location.host}/api/interactive-sessions/${sessionId}/ws`,
      );
      socketRef.current = socket;
      socket.binaryType = "arraybuffer";
      socket.onopen = () => {
        if (!terminal || !socket) return;
        setConnection("pty");
        // writeln() already moved the cursor past the "connecting" line;
        // step back up to it before clearing, or this erases the blank
        // line below it instead and leaves the message stuck on screen.
        terminal.write("\x1b[1A\r\x1b[2K");
        fit.fit();
        resize();
        if (initialInput) socket.send(new TextEncoder().encode(initialInput));
        terminal.focus();
      };
      socket.onmessage = (event) => {
        if (!terminal) return;
        const data = event.data instanceof ArrayBuffer
          ? new Uint8Array(event.data)
          : event.data;
        const text = typeof data === "string"
          ? data
          : new TextDecoder().decode(data);
        if (/No route to host|Network is unreachable/i.test(text)) {
          targetErrorRef.current = "VPN 또는 대상 경로 없음";
          setConnection("error");
        } else if (/Connection refused|Unable to connect/i.test(text)) {
          targetErrorRef.current = "대상 서비스 연결 거부";
          setConnection("error");
        } else {
          setConnection("active");
        }
        terminal.write(data);
      };
      socket.onclose = (event) => {
        if (!terminal) return;
        setConnection(
          event.code === 1000 && !targetErrorRef.current ? "closed" : "error",
        );
        terminal.write(
          `\r\n\x1b[90m[세션 종료${event.code === 1000 ? "" :
            ` · WebSocket 연결 코드 ${event.code} · 개발 서버와 백엔드 상태를 확인하세요`}]\x1b[0m\r\n`,
        );
        terminal.refresh(0, Math.max(0, terminal.rows - 1));
      };
      socket.onerror = () => {
        setConnection("error");
        terminal?.write("\r\n\x1b[31m[터미널 연결 실패]\x1b[0m\r\n");
      };
      input = terminal.onData((data) => {
        if (socket?.readyState === WebSocket.OPEN)
          socket.send(new TextEncoder().encode(data));
      });
      observer = new ResizeObserver(resize);
      observer.observe(container.current);
      resize();
    };
    void connect();
    return () => {
      disposed = true;
      observer?.disconnect();
      input?.dispose();
      socket?.close();
      socketRef.current = null;
      terminal?.dispose();
    };
  }, [sessionId, initialInput]);
  useEffect(() => {
    if (inputRequest && socketRef.current?.readyState === WebSocket.OPEN) {
      socketRef.current.send(new TextEncoder().encode(inputRequest.data));
    }
  }, [inputRequest]);
  const stop = async () => {
    await fetch(`/api/interactive-sessions/${sessionId}/stop`, {
      method: "POST",
    });
    onClose();
  };
  return (
    <section className="ptyPanel" aria-label={title}>
      <div className="ptyBar">
        <div>
          <b>{title}</b>
          <span>
            세션 #{sessionId} · Kali VM의 실제 PTY · Telnet 종료 메뉴는 Ctrl+]
          </span>
        </div>
        <span className={`ptyState ptyState--${connection}`} role="status">
          {connection === "connecting" && "연결 중"}
          {connection === "pty" && "PTY 연결됨 · 대상 응답 대기"}
          {connection === "active" && "대상 응답 확인 · 입력 가능"}
          {connection === "closed" && "종료됨"}
          {connection === "error" &&
            (targetErrorRef.current || "연결 실패")}
        </span>
        <button onClick={stop}>
          {["closed", "error"].includes(connection) ? "터미널 닫기" : "연결 종료"}
        </button>
      </div>
      <div className="ptyTerminal" ref={container} />
    </section>
  );
}
