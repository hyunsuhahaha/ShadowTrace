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
  // Set right before the operator's own "연결 종료" click closes the socket,
  // so onclose can tell "I did this on purpose" from "the socket just died"
  // and skip the reconnect loop below instead of racing the parent's
  // onClose() unmount.
  const intentionalStopRef = useRef(false);
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
    let fit: FitAddon | undefined;
    let resize: () => void = () => {};
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
    let reconnectAttempt = 0;
    let firstDropAt: number | null = null;
    let sentInitialInput = false;
    targetErrorRef.current = "";
    intentionalStopRef.current = false;

    // Reconnecting to the same sessionId re-attaches to the still-live
    // backend process (pty_manager's grace window) instead of respawning --
    // so this only ever opens a fresh WebSocket, never rebuilds the xterm
    // Terminal itself (that would drop scrollback and look like the shell
    // restarted even though the underlying process never did).
    const openSocket = () => {
      if (disposed || !terminal || !fit) return;
      const protocol = location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(
        `${protocol}://${location.host}/api/interactive-sessions/${sessionId}/ws`,
      );
      socketRef.current = socket;
      socket.binaryType = "arraybuffer";
      socket.onopen = () => {
        if (!terminal || !socket) return;
        setConnection("pty");
        reconnectAttempt = 0;
        firstDropAt = null;
        terminal.write("\x1b[1A\r\x1b[2K");
        fit!.fit();
        resize();
        if (initialInput && !sentInitialInput) {
          socket.send(new TextEncoder().encode(initialInput));
          sentInitialInput = true;
        }
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
        if (!terminal || disposed) return;
        // 4409 means the backend's own grace window already gave up on this
        // session (process killed, DB row no longer "running") -- retrying
        // the same sessionId would just get the same rejection forever, so
        // that's the one case retry() (a brand-new session) is actually for.
        // A deliberate "연결 종료" click closes cleanly too, but shouldn't
        // trigger a reconnect the parent's onClose() is about to unmount out
        // from under anyway.
        if (event.code === 4409 || intentionalStopRef.current) {
          setConnection(event.code === 1000 && !targetErrorRef.current ? "closed" : "error");
          const reason = event.code === 4409 ? " · 세션이 이미 종료되어 다시 시작해야 합니다" :
            event.code === 1000 ? "" :
            ` · WebSocket 연결 코드 ${event.code} · 개발 서버와 백엔드 상태를 확인하세요`;
          terminal.write(`\r\n\x1b[90m[세션 종료${reason}]\x1b[0m\r\n`);
          terminal.refresh(0, Math.max(0, terminal.rows - 1));
          return;
        }
        // Anything else (network blip, backgrounded tab, VPN hiccup) gets a
        // real retry instead of dumping the operator straight into "종료됨"
        // for something the underlying shell process likely never noticed --
        // capped at roughly pty_manager's own RECONNECT_GRACE_SECONDS so this
        // gives up right around when the backend would have anyway.
        firstDropAt ??= Date.now();
        if (Date.now() - firstDropAt > 50_000) {
          setConnection("error");
          terminal.write(`\r\n\x1b[31m[재연결 실패 · 터미널을 다시 여세요]\x1b[0m\r\n`);
          terminal.refresh(0, Math.max(0, terminal.rows - 1));
          return;
        }
        setConnection("connecting");
        terminal.write(`\r\n\x1b[90m[연결 끊김 · 재연결 시도 중…]\x1b[0m\r\n`);
        terminal.refresh(0, Math.max(0, terminal.rows - 1));
        const delay = Math.min(1000 * 2 ** reconnectAttempt, 8000);
        reconnectAttempt++;
        reconnectTimer = setTimeout(() => { if (!disposed) openSocket(); }, delay);
      };
      socket.onerror = () => {
        terminal?.write("\r\n\x1b[31m[터미널 연결 실패]\x1b[0m\r\n");
      };
      input?.dispose();
      input = terminal.onData((data) => {
        if (socket?.readyState === WebSocket.OPEN)
          socket.send(new TextEncoder().encode(data));
      });
    };

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
      fit = new FitAddon();
      terminal.loadAddon(fit);
      terminal.open(container.current);
      terminalRef.current = terminal;
      fitRef.current = fit;
      fit.fit();
      terminal.writeln("\x1b[90m서버 PTY에 연결하는 중입니다…\x1b[0m");
      resize = () => requestAnimationFrame(() => {
        if (disposed || !container.current || !terminal || !fit) return;
        fit.fit();
        if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({
          type: "resize", cols: terminal.cols, rows: terminal.rows,
        }));
      });
      openSocket();
      observer = new ResizeObserver(resize);
      observer.observe(container.current);
      resize();
    };
    void connect();
    return () => {
      disposed = true;
      clearTimeout(reconnectTimer);
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
    intentionalStopRef.current = true;
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
