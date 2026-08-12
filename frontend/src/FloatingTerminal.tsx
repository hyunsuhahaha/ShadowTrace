import {createContext, useContext, useEffect, useRef, useState,
  type CSSProperties, type PointerEvent as ReactPointerEvent, type ReactNode} from "react";
import {createPortal} from "react-dom";
import {statusCopy} from "./ui";
import FloatingCommandSession, {type FloatingCommandContext} from "./FloatingCommandSession";
import SmartTerminalOutput from "./SmartTerminalOutput";
import "./floating-terminal.css";

type ScanSession = {
  scanId: number;
  projectId: number;
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
type FloatingContent = {
  kind: "content";
  id: string;
  label: string;
  content: ReactNode;
  returnHash: string;
  commandContext?: FloatingCommandContext;
  executedCommand?: string;
};
type FloatingState = {kind: "scan"; session: ScanSession} | FloatingContent;
type FloatingTerminalContextValue = {
  floatingScanId?: number;
  floatingTerminalId?: string;
  floatScan: (session: ScanSession, rect: DOMRect) => void;
  floatTerminal: (terminal: Omit<FloatingContent, "kind" | "returnHash">, rect: DOMRect) => void;
  updateTerminal: (id: string, content: ReactNode) => void;
  closeTerminal: (id: string) => void;
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

export function useFloatingTerminalState() {
  return useContext(Context);
}

export function FloatingTerminalProvider({children}: {children: ReactNode}) {
  const [floating, setFloating] = useState<FloatingState | null>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
      return saved?.scanId
        ? {kind: "scan", session: {...saved, initialOutput: ""}}
        : null;
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
  const dragCleanup = useRef<() => void>();
  const outputRef = useRef<HTMLPreElement>(null);
  const session = floating?.kind === "scan" ? floating.session : null;

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
        setFloating((current) => current?.kind === "scan"
          && current.session.scanId === session.scanId
          ? {kind: "scan", session: {...current.session,
            status: item.status, exitCode: item.exit_code ?? undefined}}
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
  useEffect(() => () => dragCleanup.current?.(), []);

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
    setFloating({kind: "scan", session: docked});
    persistFrame({x: rect.x, y: rect.y, width: rect.width, height: rect.height});
  };
  const floatTerminal = (next: Omit<FloatingContent, "kind" | "returnHash">, rect: DOMRect) => {
    localStorage.removeItem(storageKey);
    setFloating({kind: "content", ...next, returnHash: location.hash || "#graph"});
    persistFrame({x: rect.x, y: rect.y, width: rect.width, height: rect.height});
  };
  const updateTerminal = (id: string, content: ReactNode) => {
    setFloating((current) => current?.kind === "content" && current.id === id
      ? {...current, content} : current);
  };
  const closeTerminal = (id: string) => setFloating((current) =>
    current?.kind === "content" && current.id === id ? null : current);
  const begin = (kind: "move" | "resize-x" | "resize-y" | "resize") =>
    (event: ReactPointerEvent<HTMLElement>) => {
    if (event.button !== 0 || (event.target as HTMLElement).closest("button")) return;
    dragCleanup.current?.();
    const start = {kind, x: event.clientX, y: event.clientY, frame: frameRef.current};
    const move = (pointer: globalThis.PointerEvent) => {
      const dx = pointer.clientX - start.x, dy = pointer.clientY - start.y;
      const next = clampFrame(start.kind === "move"
        ? {...start.frame, x: start.frame.x + dx, y: start.frame.y + dy}
        : {...start.frame,
          width: start.frame.width + (start.kind === "resize-y" ? 0 : dx),
          height: start.frame.height + (start.kind === "resize-x" ? 0 : dy)});
      frameRef.current = next;
      setFrame(next);
      pointer.preventDefault();
    };
    const finish = () => {
      localStorage.setItem(frameKey, JSON.stringify(frameRef.current));
      removeEventListener("pointermove", move);
      removeEventListener("pointerup", finish);
      removeEventListener("pointercancel", finish);
      dragCleanup.current = undefined;
    };
    addEventListener("pointermove", move);
    addEventListener("pointerup", finish);
    addEventListener("pointercancel", finish);
    dragCleanup.current = finish;
    event.preventDefault();
  };
  const dock = () => {
    if (!floating) return;
    if (floating.kind === "scan") localStorage.setItem("oscp-scan-dock", JSON.stringify({
      scanId: floating.session.scanId, targetId: floating.session.targetId,
    }));
    localStorage.removeItem(storageKey);
    setFloating(null);
    location.hash = floating.kind === "scan"
      ? floating.session.returnHash || "#scans"
      : floating.returnHash;
  };

  const resizeHandles = <>
    <i className="floatingTerminal__resize floatingTerminal__resize--x" role="separator"
      aria-label="터미널 가로 크기 조절" onPointerDown={begin("resize-x")} />
    <i className="floatingTerminal__resize floatingTerminal__resize--y" role="separator"
      aria-label="터미널 세로 크기 조절" onPointerDown={begin("resize-y")} />
    <i className="floatingTerminal__resize floatingTerminal__resize--both" role="separator"
      aria-label="터미널 크기 조절" onPointerDown={begin("resize")} />
  </>;

  return <Context.Provider value={{floatingScanId: session?.scanId,
    floatingTerminalId: floating?.kind === "content" ? floating.id : undefined,
    floatScan, floatTerminal, updateTerminal, closeTerminal}}>
    {children}
    {floating?.kind === "scan" && session && createPortal(
      <section className="floatingTerminal floatingTerminal--scan" style={{
        "--float-x": `${frame.x}px`, "--float-y": `${frame.y}px`,
        "--float-width": `${frame.width}px`, "--float-height": `${frame.height}px`,
      } as CSSProperties} aria-label={`플로팅 스캔 터미널 #${session.scanId}`}>
        <header className="floatingTerminal__bar" onPointerDown={begin("move")}>
          <span className="termDots" aria-hidden="true"><i className="termDot" />
            <i className="termDot termDot--yellow" /><i className="termDot termDot--green" /></span>
          <div><b>&gt; scan://{session.targetIp}/session/{session.scanId}</b></div>
          <small>{statusCopy[session.status] || session.status}</small>
          <button type="button" onClick={dock}>[ 원위치 ]</button>
        </header>
        <FloatingCommandSession context={{targetId: session.targetId, targetIp: session.targetIp}}
          executedCommand={session.command}>
          <div className="floatingTerminal__route"><span>operator@kali</span><b>→</b>
            <span>{session.linkType || "local"}</span><b>→</b><strong>{session.targetIp}</strong>
            <em>{stream}</em></div>
          <pre ref={outputRef} tabIndex={0}><SmartTerminalOutput output={output}
            context={{projectId: session.projectId, targetId: session.targetId,
              targetIp: session.targetIp}}
            cursor={!['completed','failed','stopped','interrupted'].includes(session.status)} /></pre>
          <footer><span>SESSION #{session.scanId}</span><span>{session.source}</span>
            <span>{session.exitCode == null ? "stdout" : `EXIT ${session.exitCode}`}</span>
            <strong>FLOATING</strong></footer>
        </FloatingCommandSession>
        {resizeHandles}
      </section>, document.body)}
    {floating?.kind === "content" && createPortal(
      <section className="floatingTerminal floatingTerminal--content" style={{
        "--float-x": `${frame.x}px`, "--float-y": `${frame.y}px`,
        "--float-width": `${frame.width}px`, "--float-height": `${frame.height}px`,
      } as CSSProperties} aria-label={`플로팅 터미널 ${floating.label}`}
        onPointerDownCapture={(event) => {
          const target = event.target as HTMLElement;
          if (target.closest("[data-terminal-drag-handle],.terminalStatus,.ptyBar"))
            begin("move")(event);
        }}>
        <FloatingCommandSession context={floating.commandContext}
          executedCommand={floating.executedCommand}>
          <div className="floatingTerminal__content">{floating.content}</div>
        </FloatingCommandSession>
        <button className="floatingTerminal__dock" type="button" onClick={dock}>[ 원위치 ]</button>
        {resizeHandles}
      </section>, document.body)}
  </Context.Provider>;
}

export function DetachableTerminal({id, label, children, floatingContent,
  commandContext, executedCommand}: {
  id: string; label: string; children: ReactNode; floatingContent?: ReactNode;
  commandContext?: FloatingCommandContext; executedCommand?: string;
}) {
  const context = useContext(Context);
  const host = useRef<HTMLDivElement>(null);
  const start = useRef<{x: number; y: number; cleanup: () => void}>();
  const isFloating = context?.floatingTerminalId === id;

  useEffect(() => {
    if (isFloating) context?.updateTerminal(id, floatingContent ?? children);
  }, [children, floatingContent, id, isFloating]);
  useEffect(() => () => start.current?.cleanup(), []);
  const beginDetach = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!context || event.button !== 0 || (event.target as HTMLElement).closest(
      "button,a,input,textarea,select,summary")) return;
    const target = event.target as HTMLElement;
    if (!target.closest("[data-terminal-drag-handle],.terminalStatus,.ptyBar")) return;
    const move = (pointer: globalThis.PointerEvent) => {
      const pending = start.current;
      if (!pending || Math.hypot(pointer.clientX - pending.x, pointer.clientY - pending.y) < 6)
        return;
      const rect = host.current?.getBoundingClientRect();
      pending.cleanup();
      if (rect) context.floatTerminal({id, label, content: floatingContent ?? children,
        commandContext, executedCommand}, rect);
    };
    const finish = () => start.current?.cleanup();
    const cleanup = () => {
      removeEventListener("pointermove", move);
      removeEventListener("pointerup", finish);
      removeEventListener("pointercancel", finish);
      start.current = undefined;
    };
    start.current = {x: event.clientX, y: event.clientY, cleanup};
    addEventListener("pointermove", move);
    addEventListener("pointerup", finish);
    addEventListener("pointercancel", finish);
  };

  if (!context) return <>{children}</>;
  return isFloating ? null : <div className="detachableTerminal" ref={host}
    onPointerDownCapture={beginDetach}>{children}</div>;
}
