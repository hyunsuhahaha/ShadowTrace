import { useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { GraphRequestDraft } from "./graphModel";
import { S } from "./graphStyles";

type GraphExchange = {
  id: number; status_code?: number | null; duration_ms: number; size: number;
  response_headers: string; error?: string;
};

export function GraphRequestPanel(props: {
  draft: GraphRequestDraft; onBack: () => void;
}) {
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState(props.draft.url);
  const [headers, setHeaders] = useState("{}");
  const [body, setBody] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [requestId, setRequestId] = useState<number | null>(null);
  const [exchange, setExchange] = useState<GraphExchange | null>(null);
  const [responseBody, setResponseBody] = useState("");
  const [state, setState] = useState<"idle" | "saving" | "sending">("idle");
  const [error, setError] = useState("");
  const [lhost, setLhost] = useState("");
  const urlInput = useRef<HTMLInputElement>(null);
  useEffect(() => {
    let cancelled = false;
    void fetch("/api/vpn/status").then((response) => response.json()).then((data) => {
      const match = /(\d{1,3}\.){3}\d{1,3}/.exec(data.tun0 || "");
      if (match && !cancelled) setLhost(match[0]);
    }).catch(() => undefined);
    return () => { cancelled = true; };
  }, []);
  const insertResponderIp = () => {
    if (!lhost) return;
    const snippet = `\\\\${lhost}\\test`;
    const pageParam = /([?&]page=)([^&]*)/.exec(url);
    if (pageParam) {
      const start = pageParam.index + pageParam[1].length;
      setUrl(url.slice(0, start) + snippet + url.slice(start + pageParam[2].length));
      return;
    }
    const start = urlInput.current?.selectionStart ?? url.length;
    const end = urlInput.current?.selectionEnd ?? url.length;
    setUrl(url.slice(0, start) + snippet + url.slice(end));
    requestAnimationFrame(() => {
      const cursor = start + snippet.length;
      urlInput.current?.focus();
      urlInput.current?.setSelectionRange(cursor, cursor);
    });
  };

  const requestPayload = () => ({
    project_id: props.draft.projectId, target_id: props.draft.targetId,
    service_id: props.draft.serviceId, name: `${method} ${new URL(url).pathname || "/"}`,
    folder: "Graph", tags: ["graph"], method, url, query: {},
    headers: JSON.parse(headers || "{}"), cookies: {}, body, body_mode: "raw",
    tls_verify: true, proxy: "", timeout: 30, follow_redirects: false,
  });
  const save = async (): Promise<number | null> => {
    setState("saving"); setError("");
    try {
      const saved = await api<{ id: number }>(
        requestId ? `/web/requests/${requestId}` : "/web/requests",
        { method: requestId ? "PUT" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(requestPayload()) },
      );
      setRequestId(saved.id); setState("idle");
      return saved.id;
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
      setState("idle"); return null;
    }
  };
  const send = async () => {
    if (!confirmed) { setError("허가된 실습 대상을 확인해 주세요."); return; }
    const id = requestId || await save();
    if (!id) return;
    setState("sending"); setError(""); setExchange(null); setResponseBody("");
    try {
      const rows = await api<GraphExchange[]>(`/web/requests/${id}/send`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ variables: {}, repeat: 1, confirmed: true }),
      });
      const result = rows.at(-1) || null;
      setExchange(result);
      if (result && !result.error) {
        const response = await fetch(`/api/web/exchanges/${result.id}/body`);
        setResponseBody(await response.text());
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally { setState("idle"); }
  };
  let responseHeaders = "";
  if (exchange?.response_headers) {
    try { responseHeaders = JSON.stringify(JSON.parse(exchange.response_headers), null, 2); }
    catch { responseHeaders = exchange.response_headers; }
  }

  return <section style={S.requestPanel} aria-label="Graph Web Request">
    <div style={S.requestPanelHead}>
      <div><small style={S.requestEyebrow}>WEB REQUEST</small>
        <h3 style={{ margin: "4px 0 0" }}>그래프에서 요청 검사</h3></div>
      <button style={S.requestBack} onClick={props.onBack}>← 실행 결과</button>
    </div>
    <div style={S.requestLine}>
      <select value={method} onChange={(e) => setMethod(e.target.value)} style={S.requestMethod}>
        {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
          .map((item) => <option key={item}>{item}</option>)}
      </select>
      <input ref={urlInput} aria-label="Request URL" value={url} onChange={(e) => setUrl(e.target.value)}
        style={S.requestUrl} />
      <button style={S.responderInsert} disabled={!lhost} onClick={insertResponderIp}
        title="URL 커서 위치 또는 page 파라미터에 UNC 경로 삽입">
        {lhost ? `RESPONDER IP · ${lhost}` : "TUN0 확인 중"}
      </button>
      <button style={S.requestSend} disabled={state !== "idle"}
        onClick={() => void send()}>{state === "sending" ? "전송 중" : "SEND"}</button>
    </div>
    <div style={S.requestGrid}>
      <label style={S.requestField}><span>HEADERS · JSON</span>
        <textarea value={headers} onChange={(e) => setHeaders(e.target.value)} rows={7} /></label>
      <label style={S.requestField}><span>BODY</span>
        <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={7} /></label>
    </div>
    <div style={S.requestActions}>
      <label><input type="checkbox" checked={confirmed}
        onChange={(e) => setConfirmed(e.target.checked)} /> 허가된 실습 대상임을 확인</label>
      <span style={{ flex: 1 }} />
      {requestId && <span style={S.requestSaved}>SAVED #{requestId}</span>}
      <button style={S.resultAction} disabled={state !== "idle"}
        onClick={() => void save()}>{state === "saving" ? "저장 중…" : "요청 저장"}</button>
    </div>
    {error && <div style={S.resultError}>{error}</div>}
    <div style={S.responsePanel}>
      <div style={S.responseHead}>
        <span>RESPONSE</span>
        {exchange && <b>{exchange.error ? "ERROR" : `HTTP ${exchange.status_code ?? "—"}`}
          <small>{exchange.duration_ms}ms · {exchange.size} bytes</small></b>}
      </div>
      {exchange?.error ? <div style={S.resultError}>{exchange.error}</div>
        : exchange ? <>
          {responseHeaders && <details><summary>응답 헤더</summary>
            <pre style={S.responsePre}>{responseHeaders}</pre></details>}
          <pre style={S.responsePre}>{responseBody || "(빈 응답)"}</pre>
        </> : <div style={S.requestEmpty}>요청을 전송하면 응답이 여기에 표시됩니다.</div>}
    </div>
  </section>;
}
