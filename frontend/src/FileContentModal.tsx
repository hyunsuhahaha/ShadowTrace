import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api } from "./api";

// Reads one file a file-tree run already discovered, over that run's own
// connection/credential -- see the backend's /read-file route for the
// "only a path this run itself found, never a freeform command" guard.
export default function FileContentModal({ runId, path, graphNodeId, onClose }: {
  runId: number; path: string; graphNodeId?: string; onClose: () => void;
}) {
  const qc = useQueryClient();
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [content, setContent] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);
  const [promote, setPromote] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [promoteError, setPromoteError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setState("loading"); setContent(""); setError(""); setCopied(false);
    setPromote("idle"); setPromoteError("");
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

  const promoteToFinding = async () => {
    setPromote("saving"); setPromoteError("");
    try {
      await api(`/post-exploitation/${runId}/promote-file`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path, graph_node_id: graphNodeId }),
      });
      setPromote("saved");
      // Findings sync into "finding" graph nodes on every graph fetch --
      // invalidate every graph query (any project id) so it happens on
      // the next one instead of waiting for some unrelated refetch.
      void qc.invalidateQueries({ queryKey: ["graph"] });
    } catch (reason) {
      setPromoteError(reason instanceof Error ? reason.message : String(reason));
      setPromote("error");
    }
  };

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
        {promote === "saved" && (
          <p style={{ color: "var(--green, #59f59a)" }}>
            Finding(Draft)으로 저장됨 — 그래프에 노드로 표시됩니다.
          </p>
        )}
        {promote === "error" && <p style={{ color: "var(--danger)" }}>{promoteError}</p>}
        <footer>
          {state === "ready" && promote !== "saved" && (
            <button disabled={promote === "saving"} onClick={() => void promoteToFinding()}>
              {promote === "saving" ? "저장 중…" : "그래프에 남기기 (Finding)"}
            </button>
          )}
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
