import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

type Target = { id: number; project_id: number; name: string; ip: string };
type SavedRequest = {
  id: number;
  project_id: number;
  target_id: number;
  service_id?: number;
  name: string;
  folder: string;
  tags: string;
  method: string;
  url: string;
  query: string;
  headers: string;
  cookies: string;
  body: string;
  body_mode: string;
  tls_verify: boolean;
  proxy: string;
  timeout: number;
  follow_redirects: boolean;
};
type Exchange = {
  id: number;
  status_code?: number;
  duration_ms: number;
  size: number;
  response_headers: string;
  response_cookies: string;
  sha256: string;
  error: string;
  created_at: string;
};
const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch("/api" + path, init);
  if (!response.ok)
    throw new Error((await response.json()).detail || response.statusText);
  return response.status === 204 ? (null as T) : response.json();
};
const empty = (target?: Target): Partial<SavedRequest> => ({
  project_id: target?.project_id,
  target_id: target?.id,
  name: "New request",
  folder: "",
  tags: "[]",
  method: "GET",
  url: target ? `http://${target.ip}/` : "http://127.0.0.1/",
  query: "{}",
  headers: "{}",
  cookies: "{}",
  body: "",
  body_mode: "raw",
  tls_verify: true,
  proxy: "",
  timeout: 30,
  follow_redirects: false,
});

export default function WebWorkspace() {
  const qc = useQueryClient();
  const [targetId, setTargetId] = useState<number>(),
    [requestId, setRequestId] = useState<number>(),
    [draft, setDraft] = useState<Partial<SavedRequest>>(empty()),
    [response, setResponse] = useState(
      "Send a user-authored request to inspect the response.",
    ),
    [exchangeId, setExchangeId] = useState<number>(),
    [compareId, setCompareId] = useState<number>(),
    [variables, setVariables] = useState("{}"),
    [repeat, setRepeat] = useState(1),
    [confirmed, setConfirmed] = useState(false),
    [error, setError] = useState("");
  const targets = useQuery({
      queryKey: ["allTargets"],
      queryFn: () => api<Target[]>("/targets"),
    }),
    requests = useQuery({
      queryKey: ["webRequests", targetId],
      queryFn: () => api<SavedRequest[]>(`/web/requests?target_id=${targetId}`),
      enabled: !!targetId,
    }),
    exchanges = useQuery({
      queryKey: ["webExchanges", requestId],
      queryFn: () => api<Exchange[]>(`/web/requests/${requestId}/exchanges`),
      enabled: !!requestId,
    }),
    comparison = useQuery({
      queryKey: ["webComparison", compareId, exchangeId],
      queryFn: () =>
        api<any>(`/web/exchanges/${compareId}/compare/${exchangeId}`),
      enabled: !!compareId && !!exchangeId && compareId !== exchangeId,
    });
  useEffect(() => {
    if (!targetId && targets.data?.[0]) setTargetId(targets.data[0].id);
  }, [targets.data, targetId]);
  useEffect(() => {
    const target = targets.data?.find((x) => x.id === targetId);
    setRequestId(undefined);
    setDraft(empty(target));
  }, [targetId, targets.data]);
  const select = (request: SavedRequest) => {
    setRequestId(request.id);
    setDraft(request);
    setExchangeId(undefined);
    setResponse("Choose a response or send this request.");
  };
  const payload = () => ({
    project_id: draft.project_id,
    target_id: draft.target_id,
    service_id: draft.service_id || null,
    name: draft.name,
    folder: draft.folder,
    tags: JSON.parse(draft.tags || "[]"),
    method: draft.method,
    url: draft.url,
    query: JSON.parse(draft.query || "{}"),
    headers: JSON.parse(draft.headers || "{}"),
    cookies: JSON.parse(draft.cookies || "{}"),
    body: draft.body,
    body_mode: draft.body_mode,
    tls_verify: draft.tls_verify,
    proxy: draft.proxy,
    timeout: draft.timeout,
    follow_redirects: draft.follow_redirects,
  });
  const save = async () => {
    try {
      setError("");
      const saved = await api<SavedRequest>(
        requestId ? `/web/requests/${requestId}` : "/web/requests",
        {
          method: requestId ? "PUT" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload()),
        },
      );
      setRequestId(saved.id);
      setDraft(saved);
      qc.invalidateQueries({ queryKey: ["webRequests", targetId] });
    } catch (e) {
      setError(String(e));
    }
  };
  const send = async () => {
    if (!requestId) {
      setError("Save the request before sending.");
      return;
    }
    try {
      setError("");
      const results = await api<Exchange[]>(`/web/requests/${requestId}/send`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          variables: JSON.parse(variables),
          repeat,
          confirmed,
        }),
      });
      await qc.invalidateQueries({ queryKey: ["webExchanges", requestId] });
      if (results[0]) openExchange(results[results.length - 1]);
    } catch (e) {
      setError(String(e));
    }
  };
  const openExchange = async (exchange: Exchange) => {
    setExchangeId(exchange.id);
    if (exchange.error) {
      setResponse(`[error] ${exchange.error}`);
      return;
    }
    const body = await fetch(`/api/web/exchanges/${exchange.id}/body`).then(
      (r) => r.arrayBuffer(),
    );
    setResponse(new TextDecoder().decode(body));
  };
  const field = (key: keyof SavedRequest, value: any) =>
    setDraft((current) => ({ ...current, [key]: value }));
  const duplicate = async () => {
    if (!requestId) return;
    const copy = await api<SavedRequest>(
      `/web/requests/${requestId}/duplicate`,
      { method: "POST" },
    );
    setRequestId(copy.id);
    setDraft(copy);
    qc.invalidateQueries({ queryKey: ["webRequests", targetId] });
  };
  return (
    <div className="webPage">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>Web Testing</small>
          </div>
        </div>
        <a href="#">← Scan Center</a>
      </header>
      <nav>
        <select
          value={targetId || ""}
          onChange={(e) => setTargetId(+e.target.value)}
        >
          <option value="">Choose target</option>
          {targets.data?.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} · {t.ip}
            </option>
          ))}
        </select>
        <button
          onClick={() => {
            setRequestId(undefined);
            setDraft(empty(targets.data?.find((x) => x.id === targetId)));
          }}
        >
          New request
        </button>
        <span>
          USER-AUTHORED REQUESTS ONLY · NO AUTOMATIC FUZZING OR VULNERABILITY
          JUDGMENT
        </span>
      </nav>
      <main className="webLayout">
        <aside>
          <h3>COLLECTION</h3>
          {requests.data?.map((r) => (
            <button
              className={r.id === requestId ? "active" : ""}
              key={r.id}
              onClick={() => select(r)}
            >
              <b>{r.name}</b>
              <small>
                {r.method} · {r.folder || "Unfiled"}
              </small>
            </button>
          ))}
        </aside>
        <section className="requestEditor">
          <div className="requestLine">
            <select
              value={draft.method}
              onChange={(e) => field("method", e.target.value)}
            >
              {["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].map(
                (x) => (
                  <option key={x}>{x}</option>
                ),
              )}
            </select>
            <input
              value={draft.url || ""}
              onChange={(e) => field("url", e.target.value)}
            />
            <button disabled={!confirmed} onClick={send}>Send</button>
          </div>
          <div className="requestMeta">
            <input
              value={draft.name || ""}
              onChange={(e) => field("name", e.target.value)}
              placeholder="Request name"
            />
            <input
              value={draft.folder || ""}
              onChange={(e) => field("folder", e.target.value)}
              placeholder="Folder"
            />
            <input
              value={draft.tags || "[]"}
              onChange={(e) => field("tags", e.target.value)}
              placeholder='["tag"]'
            />
            <button onClick={save}>Save</button>
            <button disabled={!requestId} onClick={duplicate}>
              Duplicate
            </button>
          </div>
          {error && <div className="webError">{error}</div>}
          <div className="requestGrid">
            <label>
              QUERY JSON
              <textarea
                value={draft.query || "{}"}
                onChange={(e) => field("query", e.target.value)}
              />
            </label>
            <label>
              HEADERS JSON
              <textarea
                value={draft.headers || "{}"}
                onChange={(e) => field("headers", e.target.value)}
              />
            </label>
            <label>
              COOKIES JSON
              <textarea
                value={draft.cookies || "{}"}
                onChange={(e) => field("cookies", e.target.value)}
              />
            </label>
            <label>
              BODY
              <textarea
                value={draft.body || ""}
                onChange={(e) => field("body", e.target.value)}
              />
            </label>
          </div>
          <div className="requestOptions">
            <select
              value={draft.body_mode}
              onChange={(e) => field("body_mode", e.target.value)}
            >
              <option>raw</option>
              <option>json</option>
              <option>form</option>
            </select>
            <label>
              <input
                type="checkbox"
                checked={draft.tls_verify}
                onChange={(e) => field("tls_verify", e.target.checked)}
              />{" "}
              Verify TLS
            </label>
            <label>
              <input
                type="checkbox"
                checked={draft.follow_redirects}
                onChange={(e) => field("follow_redirects", e.target.checked)}
              />{" "}
              Follow redirects
            </label>
            <input
              value={draft.proxy || ""}
              onChange={(e) => field("proxy", e.target.value)}
              placeholder="Optional proxy URL"
            />
            <input
              type="number"
              value={draft.timeout}
              onChange={(e) => field("timeout", +e.target.value)}
            />
            <input
              type="number"
              min="1"
              max="20"
              value={repeat}
              onChange={(e) => setRepeat(+e.target.value)}
            />
            <input
              value={variables}
              onChange={(e) => setVariables(e.target.value)}
              placeholder='Variables JSON, e.g. {"id":"1"}'
            />
            <label>
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />{" "}
              Authorized request
            </label>
          </div>
          <div className="responsePanel">
            <div>
              <b>RESPONSE BODY</b>
              {exchangeId && (
                <a href={`/api/web/exchanges/${exchangeId}/body?download=true`}>
                  Download raw bytes
                </a>
              )}
            </div>
            <pre>{response}</pre>
          </div>
        </section>
        <aside className="responseHistory">
          <h3>RESPONSE HISTORY</h3>
          <select
            value={compareId || ""}
            onChange={(e) => setCompareId(+e.target.value)}
          >
            <option value="">Comparison baseline</option>
            {exchanges.data
              ?.filter((item) => item.id !== exchangeId)
              .map((item) => (
                <option key={item.id} value={item.id}>
                  Response #{item.id}
                </option>
              ))}
          </select>
          {comparison.data && (
            <div className="responseDiff">
              {comparison.data.changed
                ? `Changed: ${Object.keys(comparison.data.changes).join(", ")}`
                : "No observed response changes"}
            </div>
          )}
          {exchanges.data?.map((x) => (
            <button
              className={x.id === exchangeId ? "active" : ""}
              key={x.id}
              onClick={() => openExchange(x)}
            >
              <b>{x.error ? "ERROR" : x.status_code}</b>
              <span>
                {x.duration_ms} ms · {x.size} bytes
              </span>
              <small>{new Date(x.created_at).toLocaleString()}</small>
            </button>
          ))}
        </aside>
      </main>
    </div>
  );
}
