import {createContext, useContext, useEffect, useRef, useState,
  type CSSProperties, type PointerEvent as ReactPointerEvent, type ReactNode} from "react";
import {createPortal} from "react-dom";
import {statusCopy} from "./ui";
import FloatingCommandSession, {type FloatingCommandContext} from "./FloatingCommandSession";
import XtermOutput from "./XtermOutput";
import {readTerminalFontSize, setTerminalFontSize, TERMINAL_FONT_EVENT} from "./terminalFont";
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
  // Which backend owns this session's SSE stream -- "scans" (default, Scan
  // Center's own single-target jobs) or "autorecon" (AutoReconPanel's real
  // multi-target runs). Both endpoints emit the same event shape (stdout/
  // stderr/status/snapshot), so this only changes the URL and a couple of
  // display strings, not the streaming logic itself.
  endpoint?: "scans" | "autorecon";
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
  // autoFloat PTYs (evil-winrm, every addInteractiveSession() shell, ...)
  // never had an inline/docked position to begin with -- for these, "[
  // 원위치 ]" just resets the window back to its default spot rather than
  // un-floating it, since un-floating would unmount the live PtyTerminal
  // and the backend kills the process the instant that socket closes.
  keepOnDock?: boolean;
};
type FloatingTerminalContextValue = {
  floatingScanId?: number;
  floatingEndpoint?: "scans" | "autorecon";
  isTerminalFloating: (id: string) => boolean;
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
  const [floating, setFloating] = useState<{session: ScanSession} | null>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
      return saved?.scanId ? {session: {...saved, initialOutput: ""}} : null;
    } catch { return null; }
  });
  const [frame, setFrame] = useState<Frame>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(frameKey) || "null");
      if (saved?.width) return clampFrame(saved);
    } catch { /* use default */ }
    return clampFrame({x: innerWidth - 720, y: 72, width: 680, height: 420});
  });
  // Every floated PTY (Responder, evil-winrm, an auto-floated manual shell,
  // ...) lives in this one list, rendered from a single .map() call site --
  // deliberately not split into a "primary" slot plus an "extras" list the
  // way an earlier version did. That split meant the terminal holding the
  // primary slot moved to a structurally different JSX position the moment
  // a second one was floated, which React can't reconcile in place: it
  // unmounts the old <PtyTerminal>, which closes its WebSocket, which the
  // backend reads as "the operator hung up" and SIGTERMs the still-running
  // process (Responder, in particular) even though nobody asked for that.
  // A single list keyed by terminal id never moves a mounted terminal
  // across JSX positions just because another one opened.
  const [floatingTerminals, setFloatingTerminals] = useState<Array<{
    terminal: FloatingContent; frame: Frame;
  }>>([]);
  const [output, setOutput] = useState("");
  const [stream, setStream] = useState("ATTACHING");
  const [fontSize, setFontSize] = useState(readTerminalFontSize);
  const frameRef = useRef(frame);
  const dragCleanup = useRef<() => void>();
  const session = floating?.session ?? null;

  useEffect(() => {
    if (!session) return;
    setOutput(session.initialOutput || "");
    setStream("ATTACHING");
    const events = new EventSource(`/api/${session.endpoint || "scans"}/${session.scanId}/events`);
    events.onopen = () => setStream("RX LIVE");
    events.onmessage = (event) => {
      const item = JSON.parse(event.data);
      if (item.stream === "snapshot") setOutput(item.data);
      if (item.stream === "stdout") setOutput((value) => value + item.data);
      if (item.stream === "stderr") setOutput((value) => value + `[stderr] ${item.data}`);
      if (item.stream === "imported") dispatchEvent(new CustomEvent("oscp-graph-refresh"));
      if (item.stream === "status") {
        setFloating((current) => current && current.session.scanId === session.scanId
          ? {session: {...current.session,
            status: item.status, exitCode: item.exit_code ?? undefined}}
          : current);
        if (["completed", "failed", "stopped", "interrupted"].includes(item.status)) {
          setStream("STREAM CLOSED");
          events.close();
          dispatchEvent(new CustomEvent("oscp-graph-refresh"));
        }
      }
    };
    events.onerror = () => { setStream("LINK LOST"); events.close(); };
    return () => events.close();
  }, [session?.scanId, session?.endpoint]);
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
  useEffect(() => {
    const sync = (event: Event) => setFontSize((event as CustomEvent<number>).detail);
    addEventListener(TERMINAL_FONT_EVENT, sync);
    return () => removeEventListener(TERMINAL_FONT_EVENT, sync);
  }, []);

  const persistFrame = (next: Frame) => {
    const clamped = clampFrame(next);
    frameRef.current = clamped;
    setFrame(clamped);
    localStorage.setItem(frameKey, JSON.stringify(clamped));
  };
  const floatScan = (next: ScanSession, rect: DOMRect) => {
    const docked = {...next, returnHash: location.hash || "#graph"};
    localStorage.setItem(storageKey, JSON.stringify({...docked, initialOutput: ""}));
    setFloating({session: docked});
    persistFrame({x: rect.x, y: rect.y, width: rect.width, height: rect.height});
  };
  const floatTerminal = (next: Omit<FloatingContent, "kind" | "returnHash">, rect: DOMRect) => {
    const terminal: FloatingContent = {kind: "content", ...next,
      returnHash: location.hash || "#graph"};
    setFloatingTerminals((items) => {
      if (items.some((item) => item.terminal.id === terminal.id))
        return items.map((item) => item.terminal.id === terminal.id ? {...item, terminal} : item);
      const offset = (items.length % 5) * 24;
      return [...items, {terminal, frame: clampFrame({
        x: rect.x + offset, y: rect.y + offset, width: rect.width, height: rect.height})}];
    });
  };
  const updateTerminal = (id: string, content: ReactNode) => {
    setFloatingTerminals((items) => items.map((item) => item.terminal.id === id
      ? {...item, terminal: {...item.terminal, content}} : item));
  };
  const closeTerminal = (id: string) => {
    setFloatingTerminals((items) => items.filter((item) => item.terminal.id !== id));
  };
  const isTerminalFloating = (id: string) =>
    floatingTerminals.some((item) => item.terminal.id === id);
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
    localStorage.setItem("oscp-scan-dock", JSON.stringify({
      scanId: floating.session.scanId, targetId: floating.session.targetId,
    }));
    setFloating(null);
    location.hash = floating.session.returnHash || "#scans";
  };
  const beginTerminalDrag = (id: string, kind: "move" | "resize-x" | "resize-y" | "resize") =>
    (event: ReactPointerEvent<HTMLElement>) => {
      if (event.button !== 0 || (event.target as HTMLElement).closest("button")) return;
      const active = floatingTerminals.find((item) => item.terminal.id === id);
      if (!active) return;
      dragCleanup.current?.();
      const start = {kind, x: event.clientX, y: event.clientY, frame: active.frame};
      const move = (pointer: globalThis.PointerEvent) => {
        const dx = pointer.clientX - start.x, dy = pointer.clientY - start.y;
        const next = clampFrame(start.kind === "move"
          ? {...start.frame, x: start.frame.x + dx, y: start.frame.y + dy}
          : {...start.frame,
            width: start.frame.width + (start.kind === "resize-y" ? 0 : dx),
            height: start.frame.height + (start.kind === "resize-x" ? 0 : dy)});
        setFloatingTerminals((items) => items.map((item) => item.terminal.id === id
          ? {...item, frame: next} : item));
        pointer.preventDefault();
      };
      const finish = () => {
        removeEventListener("pointermove", move); removeEventListener("pointerup", finish);
        removeEventListener("pointercancel", finish); dragCleanup.current = undefined;
      };
      addEventListener("pointermove", move); addEventListener("pointerup", finish);
      addEventListener("pointercancel", finish); dragCleanup.current = finish;
      event.preventDefault();
    };
  const dockTerminal = (terminal: FloatingContent) => {
    if (terminal.keepOnDock) {
      setFloatingTerminals((items) => items.map((item) => item.terminal.id === terminal.id
        ? {...item, frame: clampFrame({x: Math.max(8, innerWidth - 760), y: 72, width: 720, height: 460})}
        : item));
      return;
    }
    setFloatingTerminals((items) => items.filter((item) => item.terminal.id !== terminal.id));
    location.hash = terminal.returnHash;
  };

  const resizeHandles = (start: typeof begin) => <>
    <i className="floatingTerminal__resize floatingTerminal__resize--x" role="separator"
      aria-label="터미널 가로 크기 조절" onPointerDown={start("resize-x")} />
    <i className="floatingTerminal__resize floatingTerminal__resize--y" role="separator"
      aria-label="터미널 세로 크기 조절" onPointerDown={start("resize-y")} />
    <i className="floatingTerminal__resize floatingTerminal__resize--both" role="separator"
      aria-label="터미널 크기 조절" onPointerDown={start("resize")} />
  </>;

  return <Context.Provider value={{floatingScanId: session?.scanId,
    floatingEndpoint: session?.endpoint,
    isTerminalFloating, floatScan, floatTerminal, updateTerminal, closeTerminal}}>
    {children}
    {floatingTerminals.map(({terminal, frame: itemFrame}) => createPortal(
      <section key={terminal.id} className="floatingTerminal floatingTerminal--content" style={{
        "--float-x": `${itemFrame.x}px`, "--float-y": `${itemFrame.y}px`,
        "--float-width": `${itemFrame.width}px`, "--float-height": `${itemFrame.height}px`,
      } as CSSProperties} aria-label={`플로팅 터미널 ${terminal.label}`}
        onPointerDownCapture={(event) => {
          const target = event.target as HTMLElement;
          if (target.closest("[data-terminal-drag-handle],.terminalStatus,.ptyBar"))
            beginTerminalDrag(terminal.id, "move")(event);
        }}>
        <FloatingCommandSession context={terminal.commandContext}
          executedCommand={terminal.executedCommand}>
          <div className="floatingTerminal__content">{terminal.content}</div>
        </FloatingCommandSession>
        <button className="floatingTerminal__dock" type="button"
          onClick={() => dockTerminal(terminal)}>[ 원위치 ]</button>
        {resizeHandles((kind) => beginTerminalDrag(terminal.id, kind))}
      </section>, document.body))}
    {floating && session && createPortal(
      <section className="floatingTerminal floatingTerminal--scan" style={{
        "--float-x": `${frame.x}px`, "--float-y": `${frame.y}px`,
        "--float-width": `${frame.width}px`, "--float-height": `${frame.height}px`,
      } as CSSProperties} aria-label={`플로팅 스캔 터미널 #${session.scanId}`}>
        <header className="floatingTerminal__bar" onPointerDown={begin("move")}>
          <span className="termDots" aria-hidden="true"><i className="termDot" />
            <i className="termDot termDot--yellow" /><i className="termDot termDot--green" /></span>
          <div><b>&gt; {session.endpoint === "autorecon"
            ? `autorecon://${session.targetIp}/run/${session.scanId}`
            : `scan://${session.targetIp}/session/${session.scanId}`}</b></div>
          <small>{statusCopy[session.status] || session.status}</small>
          <div className="floatingTerminal__fontControls" aria-label="터미널 글자 크기">
            <button type="button" title="글자 축소" aria-label="터미널 글자 축소"
              onClick={() => setTerminalFontSize(fontSize - 1)}>-</button>
            <b>{fontSize}</b>
            <button type="button" title="글자 확대" aria-label="터미널 글자 확대"
              onClick={() => setTerminalFontSize(fontSize + 1)}>+</button>
          </div>
          <button type="button" onClick={dock}>[ 원위치 ]</button>
        </header>
        <FloatingCommandSession context={{targetId: session.targetId, targetIp: session.targetIp}}
          executedCommand={session.command}>
          <div className="floatingTerminal__route"><span>operator@kali</span><b>→</b>
            <span>{session.linkType || "local"}</span><b>→</b><strong>{session.targetIp}</strong>
            <em>{stream}</em></div>
          <XtermOutput output={output}
            cursor={!['completed','failed','stopped','interrupted'].includes(session.status)}
            ariaLabel={`스캔 #${session.scanId} xterm 출력`} />
          <footer><span>SESSION #{session.scanId}</span><span>{session.source}</span>
            <span>{session.exitCode == null ? "stdout" : `EXIT ${session.exitCode}`}</span>
            <strong>FLOATING</strong></footer>
        </FloatingCommandSession>
        {resizeHandles(begin)}
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
  const isFloating = context?.isTerminalFloating(id) || false;

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
