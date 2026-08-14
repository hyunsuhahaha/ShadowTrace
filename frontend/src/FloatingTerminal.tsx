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
type FloatingState = {kind: "scan"; session: ScanSession} | FloatingContent;
type FloatingTerminalContextValue = {
  floatingScanId?: number;
  floatingTerminalId?: string;
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
  const [floating, setFloating] = useState<FloatingState | null>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) || "null");
      return saved?.scanId
        ? {kind: "scan", session: {...saved, initialOutput: ""}}
        : null;
    } catch { return null; }
  });
  const floatingRef = useRef<FloatingState | null>(floating);
  const [frame, setFrame] = useState<Frame>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(frameKey) || "null");
      if (saved?.width) return clampFrame(saved);
    } catch { /* use default */ }
    return clampFrame({x: innerWidth - 720, y: 72, width: 680, height: 420});
  });
  const [extraFloating, setExtraFloating] = useState<Array<{
    terminal: FloatingContent; frame: Frame;
  }>>([]);
  const [output, setOutput] = useState("");
  const [stream, setStream] = useState("ATTACHING");
  const [fontSize, setFontSize] = useState(readTerminalFontSize);
  const frameRef = useRef(frame);
  const dragCleanup = useRef<() => void>();
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
    const stored = {...docked, initialOutput: ""};
    localStorage.setItem(storageKey, JSON.stringify(stored));
    floatingRef.current = {kind: "scan", session: docked};
    setFloating(floatingRef.current);
    persistFrame({x: rect.x, y: rect.y, width: rect.width, height: rect.height});
  };
  const floatTerminal = (next: Omit<FloatingContent, "kind" | "returnHash">, rect: DOMRect) => {
    localStorage.removeItem(storageKey);
    const terminal: FloatingContent = {kind: "content", ...next,
      returnHash: location.hash || "#graph"};
    const current = floatingRef.current;
    if (current?.kind === "content" && current.id !== next.id)
      setExtraFloating((items) => items.some((item) => item.terminal.id === current.id)
        ? items : [...items, {terminal: current, frame: frameRef.current}]);
    floatingRef.current = terminal;
    setFloating(terminal);
    const offset = (extraFloating.length % 5) * 24;
    persistFrame({x: rect.x + offset, y: rect.y + offset,
      width: rect.width, height: rect.height});
  };
  const updateTerminal = (id: string, content: ReactNode) => {
    setFloating((current) => current?.kind === "content" && current.id === id
      ? {...current, content} : current);
    setExtraFloating((items) => items.map((item) => item.terminal.id === id
      ? {...item, terminal: {...item.terminal, content}} : item));
  };
  const closeTerminal = (id: string) => {
    setFloating((current) => {
      const next = current?.kind === "content" && current.id === id ? null : current;
      floatingRef.current = next;
      return next;
    });
    setExtraFloating((items) => items.filter((item) => item.terminal.id !== id));
  };
  const isTerminalFloating = (id: string) =>
    (floating?.kind === "content" && floating.id === id)
    || extraFloating.some((item) => item.terminal.id === id);
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
    if (floating.kind === "content" && floating.keepOnDock) {
      persistFrame({x: Math.max(8, innerWidth - 760), y: 72, width: 720, height: 460});
      return;
    }
    if (floating.kind === "scan") localStorage.setItem("oscp-scan-dock", JSON.stringify({
      scanId: floating.session.scanId, targetId: floating.session.targetId,
    }));
    localStorage.removeItem(storageKey);
    floatingRef.current = null;
    setFloating(null);
    location.hash = floating.kind === "scan"
      ? floating.session.returnHash || "#scans"
      : floating.returnHash;
  };
  const beginExtra = (id: string, kind: "move" | "resize-x" | "resize-y" | "resize") =>
    (event: ReactPointerEvent<HTMLElement>) => {
      if (event.button !== 0 || (event.target as HTMLElement).closest("button")) return;
      const active = extraFloating.find((item) => item.terminal.id === id);
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
        setExtraFloating((items) => items.map((item) => item.terminal.id === id
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
  const dockExtra = (terminal: FloatingContent) => {
    if (terminal.keepOnDock) {
      setExtraFloating((items) => items.map((item) => item.terminal.id === terminal.id
        ? {...item, frame: clampFrame({x: Math.max(8, innerWidth - 760), y: 72, width: 720, height: 460})}
        : item));
      return;
    }
    setExtraFloating((items) => items.filter((item) => item.terminal.id !== terminal.id));
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
    floatingTerminalId: floating?.kind === "content" ? floating.id : undefined,
    isTerminalFloating, floatScan, floatTerminal, updateTerminal, closeTerminal}}>
    {children}
    {extraFloating.map(({terminal, frame: extraFrame}) => createPortal(
      <section key={terminal.id} className="floatingTerminal floatingTerminal--content" style={{
        "--float-x": `${extraFrame.x}px`, "--float-y": `${extraFrame.y}px`,
        "--float-width": `${extraFrame.width}px`, "--float-height": `${extraFrame.height}px`,
      } as CSSProperties} aria-label={`플로팅 터미널 ${terminal.label}`}
        onPointerDownCapture={(event) => {
          const target = event.target as HTMLElement;
          if (target.closest("[data-terminal-drag-handle],.terminalStatus,.ptyBar"))
            beginExtra(terminal.id, "move")(event);
        }}>
        <FloatingCommandSession context={terminal.commandContext}
          executedCommand={terminal.executedCommand}>
          <div className="floatingTerminal__content">{terminal.content}</div>
        </FloatingCommandSession>
        <button className="floatingTerminal__dock" type="button"
          onClick={() => dockExtra(terminal)}>[ 원위치 ]</button>
        {resizeHandles((kind) => beginExtra(terminal.id, kind))}
      </section>, document.body))}
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
