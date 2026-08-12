import {useState, type FormEvent, type ReactNode} from "react";
import {api} from "./api";
import PtyTerminal from "./PtyTerminal";

export type FloatingCommandContext = {
  targetId: number;
  targetIp: string;
  serviceId?: number;
};

export default function FloatingCommandSession({context, executedCommand, children}: {
  context?: FloatingCommandContext;
  executedCommand?: string;
  children: ReactNode;
}) {
  const [draft, setDraft] = useState("");
  const [opening, setOpening] = useState(false);
  const [error, setError] = useState("");
  const [pty, setPty] = useState<{id: number; command: string}>();

  const open = async (event: FormEvent) => {
    event.preventDefault();
    const command = draft.trim();
    if (!context || !command || opening) return;
    setOpening(true);
    setError("");
    try {
      const session = await api<{id: number}>("/interactive-sessions/manual", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          target_id: context.targetId,
          service_id: context.serviceId || null,
        }),
      });
      setPty({id: session.id, command});
      setDraft("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setOpening(false);
    }
  };

  if (pty) return <div className="floatingCommandSession floatingCommandSession--pty">
    <div className="floatingCommandSession__executed"><b>$</b><code>{pty.command}</code></div>
    <PtyTerminal sessionId={pty.id} title={`operator@kali · ${context?.targetIp || "target"}`}
      initialInput={`${pty.command}\r`} onClose={() => setPty(undefined)} />
  </div>;

  return <div className="floatingCommandSession">
    {executedCommand && <div className="floatingCommandSession__executed">
      <b>$</b><code>{executedCommand}</code>
    </div>}
    <div className="floatingCommandSession__output">{children}</div>
    {context && <form className="floatingCommandSession__prompt" onSubmit={open}>
      <label htmlFor="floating-terminal-command">
        <span>operator@kali:{context.targetIp}$</span>
        <input id="floating-terminal-command" aria-label="플로팅 터미널 명령"
          autoComplete="off" spellCheck={false} value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="다음 명령을 입력하세요" />
      </label>
      <button type="submit" disabled={!draft.trim() || opening}>
        {opening ? "OPENING" : "PTY ↵"}
      </button>
      {error && <span className="floatingCommandSession__error" role="alert">{error}</span>}
    </form>}
  </div>;
}
