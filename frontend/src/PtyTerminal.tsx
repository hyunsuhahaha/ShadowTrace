import {useEffect, useRef, useState} from "react";
import {Terminal} from "@xterm/xterm";
import {FitAddon} from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import {readTerminalFontSize, setTerminalFontSize, TERMINAL_FONT_EVENT} from "./terminalFont";

export type PtyTerminalProps = {
  sessionId: number;
  onClose: () => void;
  initialInput?: string;
  title?: string;
  inputRequest?: {id: number; data: string};
};

export default function PtyTerminal({sessionId, onClose, initialInput = "",
  title = "대화형 터미널", inputRequest}: PtyTerminalProps) {
  const container = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLElement>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const targetErrorRef = useRef("");
  const [fontSize, setFontSize] = useState(readTerminalFontSize);
  const [connection, setConnection] = useState<
    "connecting" | "pty" | "active" | "closed" | "error"
  >("connecting");
  // window.confirm() is unreliable here: some browsers/embeds silently
  // return false without ever showing the dialog (e.g. after Chrome's
  // "prevent additional dialogs" auto-suppression kicks in), which made
  // the button look completely dead. A same-panel two-click confirm
  // always renders, so there's no dialog to suppress.
  const [confirmingStop, setConfirmingStop] = useState(false);
  const confirmTimer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => () => clearTimeout(confirmTimer.current), []);

  useEffect(() => {
    panel.current?.scrollIntoView({behavior: "smooth", block: "center"});
  }, [sessionId]);
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
        fontSize,
        fontWeight: "normal",
        fontWeightBold: "bold",
        letterSpacing: 0,
        lineHeight: 1.15,
        scrollback: 5000,
        theme: {background: "#050809", foreground: "#c9d5d8", cursor: "#9fe870"},
      });
      const fit = new FitAddon();
      terminal.loadAddon(fit);
      terminal.open(container.current);
      terminalRef.current = terminal;
      fitRef.current = fit;
      fit.fit();
      terminal.writeln("\x1b[90m서버 PTY에 연결하는 중입니다…\x1b[0m");
      const resize = () => requestAnimationFrame(() => {
        if (disposed || !container.current || !terminal) return;
        fit.fit();
        if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({
          type: "resize", cols: terminal.cols, rows: terminal.rows,
        }));
      });
      const protocol = location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(
        `${protocol}://${location.host}/api/interactive-sessions/${sessionId}/ws`,
      );
      socketRef.current = socket;
      socket.binaryType = "arraybuffer";
      socket.onopen = () => {
        if (!terminal || !socket) return;
        setConnection("pty");
        terminal.write("\x1b[1A\r\x1b[2K");
        fit.fit();
        resize();
        if (initialInput) socket.send(new TextEncoder().encode(initialInput));
        terminal.focus();
      };
      socket.onmessage = (event) => {
        if (!terminal) return;
        const data = event.data instanceof ArrayBuffer ? new Uint8Array(event.data) : event.data;
        const text = typeof data === "string" ? data : new TextDecoder().decode(data);
        if (/No route to host|Network is unreachable/i.test(text)) {
          targetErrorRef.current = "VPN 또는 대상 경로 없음";
          setConnection("error");
        } else if (/Connection refused|Unable to connect/i.test(text)) {
          targetErrorRef.current = "대상 서비스 연결 거부";
          setConnection("error");
        } else setConnection("active");
        terminal.write(data);
      };
      socket.onclose = (event) => {
        if (!terminal) return;
        setConnection(event.code === 1000 && !targetErrorRef.current ? "closed" : "error");
        const reason = event.code === 1000 ? "" :
          event.code === 4409 ? " · 세션이 이미 종료되어 다시 시작해야 합니다" :
          ` · WebSocket 연결 코드 ${event.code} · 개발 서버와 백엔드 상태를 확인하세요`;
        terminal.write(`\r\n\x1b[90m[세션 종료${reason}]\x1b[0m\r\n`);
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
      terminalRef.current = null;
      fitRef.current = null;
      terminal?.dispose();
    };
  }, [sessionId, initialInput]);
  useEffect(() => {
    const sync = (event: Event) => setFontSize((event as CustomEvent<number>).detail);
    addEventListener(TERMINAL_FONT_EVENT, sync);
    return () => removeEventListener(TERMINAL_FONT_EVENT, sync);
  }, []);
  useEffect(() => {
    if (!terminalRef.current) return;
    terminalRef.current.options.fontSize = fontSize;
    requestAnimationFrame(() => fitRef.current?.fit());
  }, [fontSize]);
  useEffect(() => {
    if (inputRequest && socketRef.current?.readyState === WebSocket.OPEN)
      socketRef.current.send(new TextEncoder().encode(inputRequest.data));
  }, [inputRequest]);

  const stop = async () => {
    if (["pty", "active"].includes(connection) && !confirmingStop) {
      setConfirmingStop(true);
      confirmTimer.current = setTimeout(() => setConfirmingStop(false), 4000);
      return;
    }
    clearTimeout(confirmTimer.current);
    setConfirmingStop(false);
    await fetch(`/api/interactive-sessions/${sessionId}/stop`, {method: "POST"});
    onClose();
  };

  return <section className="ptyPanel" aria-label={title} ref={panel}>
    <div className="ptyBar" data-terminal-drag-handle title="드래그하여 터미널 분리">
      <span className="termDots" aria-hidden="true">
        <i className="termDot" /><i className="termDot termDot--yellow" />
        <i className="termDot termDot--green" />
      </span>
      <div><b>{title}</b><span>세션 #{sessionId} · Kali VM의 실제 PTY · Telnet 종료 메뉴는 Ctrl+]</span></div>
      <span className={`ptyState ptyState--${connection}`} role="status">
        {connection === "connecting" && "연결 중"}
        {connection === "pty" && "PTY 연결됨 · 대상 응답 대기"}
        {connection === "active" && "대상 응답 확인 · 입력 가능"}
        {connection === "closed" && "종료됨"}
        {connection === "error" && (targetErrorRef.current || "연결 실패")}
      </span>
      <div className="ptyFontControls" aria-label="터미널 글자 크기">
        <button type="button" title="글자 축소" aria-label="터미널 글자 축소"
          onClick={() => setTerminalFontSize(fontSize - 1)}>-</button>
        <output>{fontSize}</output>
        <button type="button" title="글자 확대" aria-label="터미널 글자 확대"
          onClick={() => setTerminalFontSize(fontSize + 1)}>+</button>
      </div>
      <button onClick={stop} className={confirmingStop ? "ptyStopArmed" : undefined}>
        {["closed", "error"].includes(connection) ? "터미널 닫기"
          : confirmingStop ? "정말 종료? (다시 클릭)" : "연결 종료"}
      </button>
    </div>
    <div className="ptyTerminal" ref={container} />
  </section>;
}
