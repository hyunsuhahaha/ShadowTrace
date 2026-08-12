import {createContext, useContext, useEffect, useRef, useState,
  type CSSProperties, type PointerEvent, type ReactNode} from "react";
import {createPortal} from "react-dom";
import {statusCopy} from "./ui";
import "./floating-terminal.css";

type ScanSession = {
  scanId: number;
  targetId: number;
  targetIp: string;
  command: string;
  source: string;
  status: string;
  exitCode?: number;
  linkType: string;
  initialOutput: string;
  returnHash?: string;
};
type Frame = {x: number; y: number; width: number; height: number};
type FloatingTerminalContextValue = {
  floatingScanId?: number;
  floatScan: (session: ScanSession, rect: DOMRect) => void;
};

const storageKey = "oscp-floating-scan-terminal";
const frameKey = "oscp-floating-terminal-frame";
const minWidth = 440;
const minHeight = 280;
const edge = 8;
const Context = createContext<FloatingTerminalContextValue | null>(null);

const clampFrame = (frame: Frame): Frame => {
  const width = Math.min(Math.max(minWidth, frame.width), Math.max(minWidth, innerWidth - edge * 2));
  const height = Math.min(Math.max(minHeight, frame.height), Math.max(minHeight, innerHeight - edge * 2));
  return {
    width, height,
    x: Math.min(Math.max(edge, frame.x), Math.max(edge, innerWidth - width - edge)),
    y: Math.min(Math.max(edge, frame.y), Math.max(edge, innerHeight - height - edge)),
  };
};

export function useFloatingTerminal() {
  const value = useContext(Context);
  if (!value) throw new Error("useFloatingTerminal must be used inside FloatingTerminalProvider");
  return value;
}

export function FloatingTerminalProvider({children}: {children: ReactNode}) {
  const [session, setSession] = useState<ScanSession | null>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
      return saved?.scanId ? {...saved, initialOutput: ""} : null;
    } catch { return null; }
  });
  const [frame, setFrame] = useState<Frame>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(frameKey) || "null");
      if (saved?.width) return clampFrame(saved);
    } catch { /* use default */ }
    return clampFrame({x: innerWidth - 720, y: 72, width: 680, height: 420});
  });
  const [output, setOutput] = useState("");
  const [stream, setStream] = useState("ATTACHING");
  const frameRef = useRef(frame);
  const drag = useRef<{kind: "move" | "resize"; x: number; y: number; frame: Frame}>();
  const outputRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (!session) return;
    setOutput(session.initialOutput || "");
    setStream("ATTACHING");
    const events = new EventSource(`/api/scans/${session.scanId}/events`);
    events.onopen = () => setStream("RX LIVE");
    events.onmessage = (event) => {
      const item = JSON.parse(event.data);
      if (item.stream === "snapshot") setOutput(item.data);
      if (item.stream === "stdout") setOutput((value) => value + item.data);
      if (item.stream === "stderr") setOutput((value) => value + `[stderr] ${item.data}`);
      if (item.stream === "status") {
        setSession((current) => current && current.scanId === session.scanId
          ? {...current, status: item.status, exitCode: item.exit_code ?? undefined}
          : current);
        if (["completed", "failed", "stopped", "interrupted"].includes(item.status)) {
          setStream("STREAM CLOSED");
          events.close();
        }
      }
    };
    events.onerror = () => { setStream("LINK LOST"); events.close(); };
    return () => events.close();
  }, [session?.scanId]);
  useEffect(() => {
    if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight;
  }, [output]);
  useEffect(() => {
    const resize = () => {
      const clamped = clampFrame(frameRef.current);
      frameRef.current = clamped;
      setFrame(clamped);
      localStorage.setItem(frameKey, JSON.stringify(clamped));
    };
    addEventListener("resize", resize);
    return () => removeEventListener("resize", resize);
  }, []);

  const persistFrame = (next: Frame) => {
    const clamped = clampFrame(next);
    frameRef.current = clamped;
    setFrame(clamped);
    localStorage.setItem(frameKey, JSON.stringify(clamped));
  };
  const floatScan = (next: ScanSession, rect: DOMRect) => {
    const docked = {...next, returnHash: location.hash || "#graph"};
    const stored = {...docked, initialOutput: ""};
    localStorage.setItem(storageKey, JSON.stringify(stored));
    setSession(docked);
    persistFrame({x: rect.x, y: rect.y, width: rect.width, height: rect.height});
  };
  const begin = (kind: "move" | "resize") => (event: PointerEvent<HTMLElement>) => {
    if (event.button !== 0 || (event.target as HTMLElement).closest("button")) return;
    drag.current = {kind, x: event.clientX, y: event.clientY, frame};
    event.currentTarget.setPointerCapture(event.pointerId);
    event.preventDefault();
  };
  const move = (event: PointerEvent<HTMLElement>) => {
    const active = drag.current;
    if (!active || !event.currentTarget.hasPointerCapture(event.pointerId)) return;
    const dx = event.clientX - active.x, dy = event.clientY - active.y;
    const next = clampFrame(active.kind === "move"
      ? {...active.frame, x: active.frame.x + dx, y: active.frame.y + dy}
      : {...active.frame, width: active.frame.width + dx, height: active.frame.height + dy});
    frameRef.current = next;
    setFrame(next);
  };
  const finish = (event: PointerEvent<HTMLElement>) => {
    if (!drag.current) return;
    drag.current = undefined;
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
    localStorage.setItem(frameKey, JSON.stringify(frameRef.current));
  };
  const dock = () => {
    if (!session) return;
    localStorage.setItem("oscp-scan-dock", JSON.stringify({
      scanId: session.scanId, targetId: session.targetId,
    }));
    localStorage.removeItem(storageKey);
    setSession(null);
    location.hash = session.returnHash || "#scans";
  };

  return <Context.Provider value={{floatingScanId: session?.scanId, floatScan}}>
    {children}
    {session && createPortal(
      <section className="floatingTerminal" style={{
        "--float-x": `${frame.x}px`, "--float-y": `${frame.y}px`,
        "--float-width": `${frame.width}px`, "--float-height": `${frame.height}px`,
      } as CSSProperties} aria-label={`플로팅 스캔 터미널 #${session.scanId}`}>
        <header className="floatingTerminal__bar" onPointerDown={begin("move")}
          onPointerMove={move} onPointerUp={finish} onPointerCancel={finish}>
          <span className="termDots" aria-hidden="true"><i className="termDot" />
            <i className="termDot termDot--yellow" /><i className="termDot termDot--green" /></span>
          <div><b>&gt; scan://{session.targetIp}/session/{session.scanId}</b>
            <span>{session.command}</span></div>
          <small>{statusCopy[session.status] || session.status}</small>
          <button type="button" onClick={dock}>[ 원위치 ]</button>
        </header>
        <div className="floatingTerminal__route"><span>operator@kali</span><b>→</b>
          <span>{session.linkType || "local"}</span><b>→</b><strong>{session.targetIp}</strong>
          <em>{stream}</em></div>
        <pre ref={outputRef} tabIndex={0}><code>{output}</code>
          {!['completed','failed','stopped','interrupted'].includes(session.status) &&
            <i className="scanTranscript__cursor" aria-hidden="true" />}</pre>
        <footer><span>SESSION #{session.scanId}</span><span>{session.source}</span>
          <span>{session.exitCode == null ? "stdout" : `EXIT ${session.exitCode}`}</span>
          <strong>FLOATING</strong></footer>
        <i className="floatingTerminal__resize" role="separator" aria-label="터미널 크기 조절"
          onPointerDown={begin("resize")} onPointerMove={move} onPointerUp={finish}
          onPointerCancel={finish} />
      </section>, document.body)}
  </Context.Provider>;
}
