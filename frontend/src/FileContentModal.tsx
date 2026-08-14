import { useEffect, useState } from "react";
import { api } from "./api";

// Reads one file a file-tree run already discovered, over that run's own
// connection/credential -- see the backend's /read-file route for the
// "only a path this run itself found, never a freeform command" guard.
export default function FileContentModal({ runId, path, onClose }: {
  runId: number; path: string; onClose: () => void;
}) {
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [content, setContent] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setState("loading"); setContent(""); setError(""); setCopied(false);
    api<{ content: string }>(`/post-exploitation/${runId}/read-file`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    }).then((result) => {
      if (cancelled) return;
      setContent(result.content); setState("ready");
    }).catch((reason) => {
      if (cancelled) return;
      setError(reason instanceof Error ? reason.message : String(reason));
      setState("error");
    });
    return () => { cancelled = true; };
  }, [runId, path]);

  return (
    <div className="modal" role="dialog" aria-label={`파일 내용 · ${path}`} onClick={onClose}>
      <div onClick={(event) => event.stopPropagation()}>
        <span>FILE</span>
        <h2 style={{ wordBreak: "break-all", fontSize: 15 }}>{path}</h2>
        {state === "loading" && <p>불러오는 중…</p>}
        {state === "error" && <p style={{ color: "var(--danger)" }}>{error}</p>}
        {state === "ready" && (
          <pre className="fileContentBody">{content || "(빈 파일)"}</pre>
        )}
        <footer>
          {state === "ready" && (
            <button onClick={() => {
              void navigator.clipboard.writeText(content);
              setCopied(true);
            }}>{copied ? "복사됨" : "복사"}</button>
          )}
          <button onClick={onClose}>닫기</button>
        </footer>
      </div>
    </div>
  );
}
