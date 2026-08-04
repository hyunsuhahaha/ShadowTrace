import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import IntruderPanel from "./IntruderPanel";
import SqlPayloadReference from "./SqlPayloadReference";
import ProxyPanel from "./ProxyPanel";
import { parseCurl } from "./curlImport";
import { EmptyState, ErrorState, LoadingState } from "./ui";

type Target = { id: number; project_id: number; name: string; ip: string };
export type SavedRequest = {
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
export type WebLaunchContext = {targetId: number; serviceId: number; url: string};
export const parseWebLaunchContext = (raw: string | null): WebLaunchContext | undefined => {
  try {
    const value = JSON.parse(raw || "null");
    return Number.isInteger(value?.targetId) && Number.isInteger(value?.serviceId)
      && /^https?:\/\//.test(value?.url) ? value : undefined;
  } catch {
    return undefined;
  }
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
    [workspaceTab, setWorkspaceTab] =
      useState<"request" | "intruder" | "sqli" | "proxy" | "results">("request"),
    [intruderSeed, setIntruderSeed] = useState<{ token: number; values: string[] }>(),
    [curlInput, setCurlInput] = useState(""),
    [error, setError] = useState("");
  const sendToIntruder = (payloads: string[]) => {
    setIntruderSeed({ token: Date.now(), values: payloads });
    setWorkspaceTab("intruder");
  };
  const importCurl = () => {
    const parsed = parseCurl(curlInput);
    if (!parsed) {
      setError("유효한 curl 명령어가 아닙니다. 브라우저 Network 탭에서 \"Copy as cURL\"로 복사한 값을 붙여넣으세요.");
      return;
    }
    setError("");
    setDraft((current) => ({
      ...current,
      method: parsed.method,
      url: parsed.url,
      headers: JSON.stringify(parsed.headers),
      cookies: JSON.stringify(parsed.cookies),
      body: parsed.body,
      body_mode: "raw",
    }));
    setCurlInput("");
  };
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
    if (!targetId && targets.data?.[0]) {
      const launch = parseWebLaunchContext(localStorage.getItem("oscp-web-launch"));
      setTargetId(targets.data.find((target) => target.id === launch?.targetId)?.id
        || targets.data[0].id);
    }
  }, [targets.data, targetId]);
  useEffect(() => {
    const target = targets.data?.find((x) => x.id === targetId);
    const launch = parseWebLaunchContext(localStorage.getItem("oscp-web-launch"));
    setRequestId(undefined);
    setDraft(launch && launch.targetId === targetId
      ? {...empty(target), service_id: launch.serviceId, url: launch.url}
      : empty(target));
    if (launch?.targetId === targetId) localStorage.removeItem("oscp-web-launch");
  }, [targetId, targets.data]);
  useEffect(() => {
    if (targetId) dispatchEvent(new CustomEvent("oscp-target-change", {detail: targetId}));
  }, [targetId]);
  const select = (request: SavedRequest) => {
    setRequestId(request.id);
    setDraft(request);
    setExchangeId(undefined);
    setResponse("응답을 선택하거나 이 요청을 전송하세요.");
  };
  const openCapturedRequest = (request: SavedRequest) => {
    select(request);
    setWorkspaceTab("request");
  };
  const sendCapturedToIntruder = (request: SavedRequest) => {
    select(request);
    setWorkspaceTab("intruder");
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
      setError("전송하기 전에 요청을 저장하세요.");
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
      setResponse(`[오류] ${exchange.error}`);
      return;
    }
    const body = await fetch(`/api/web/exchanges/${exchange.id}/body`).then(
      (r) => r.arrayBuffer(),
    );
    setResponse(new TextDecoder().decode(body));
  };
  const field = (key: keyof SavedRequest, value: any) =>
    setDraft((current) => ({ ...current, [key]: value }));
  const deleteRequest = async (request: SavedRequest) => {
    if (!confirm(`"${request.name}" 요청과 저장된 응답 이력을 삭제할까요? 되돌릴 수 없습니다.`)) return;
    try {
      await api(`/web/requests/${request.id}`, { method: "DELETE" });
      if (request.id === requestId) {
        setRequestId(undefined);
        setDraft(empty(targets.data?.find((x) => x.id === targetId)));
        setExchangeId(undefined);
        setResponse("Send a user-authored request to inspect the response.");
      }
      qc.invalidateQueries({ queryKey: ["webRequests", targetId] });
    } catch (e) {
      setError(String(e));
    }
  };
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
            <small>Web 테스트</small>
          </div>
        </div>
        <a href="#">← Scan Center</a>
      </header>
      <nav>
        <select
          value={targetId || ""}
          onChange={(e) => setTargetId(+e.target.value)}
        >
          <option value="">대상 선택</option>
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
          새 요청
        </button>
        <div className="webModeTabs" role="tablist" aria-label="Web Testing 작업">
          <button role="tab" aria-selected={workspaceTab === "request"}
            onClick={() => setWorkspaceTab("request")}>Request</button>
          <button role="tab" aria-selected={workspaceTab === "intruder"}
            onClick={() => setWorkspaceTab("intruder")}>Intruder</button>
          <button role="tab" aria-selected={workspaceTab === "sqli"}
            onClick={() => setWorkspaceTab("sqli")}>SQLi 참고</button>
          <button role="tab" aria-selected={workspaceTab === "proxy"}
            onClick={() => setWorkspaceTab("proxy")}>Proxy</button>
          <button role="tab" aria-selected={workspaceTab === "results"}
            onClick={() => setWorkspaceTab("results")}>Response</button>
        </div>
      </nav>
      <main className="webLayout">
        <aside>
          <h3>컬렉션</h3>
          {requests.isLoading && <LoadingState label="요청 목록을 불러오는 중" />}
          {requests.error && <ErrorState message={String(requests.error)} />}
          {!requests.isLoading && !requests.data?.length &&
            <EmptyState title="저장된 요청이 없습니다" description="새 요청을 만들어 저장하세요." />}
          {requests.data?.map((r) => (
            <div className="collectionRow" key={r.id}>
              <button
                className={r.id === requestId ? "active" : ""}
                onClick={() => select(r)}
              >
                <b>{r.name}</b>
                <small>
                  {r.method} · {r.folder || "분류 없음"}
                </small>
              </button>
              <button className="collectionDelete" aria-label={`${r.name} 삭제`}
                onClick={() => deleteRequest(r)}>
                삭제
              </button>
            </div>
          ))}
        </aside>
        <section className={`requestEditor requestEditor--${workspaceTab}`}>
          {workspaceTab === "intruder" ? (
            <IntruderPanel requestId={requestId} timeout={draft.timeout || 30}
              projectId={draft.project_id} targetId={draft.target_id}
              serviceId={draft.service_id} seed={intruderSeed}
              onGoToRequest={() => setWorkspaceTab("request")} />
          ) : workspaceTab === "sqli" ? (
            <SqlPayloadReference onSendToIntruder={sendToIntruder} />
          ) : workspaceTab === "proxy" ? (
            <ProxyPanel projectId={targets.data?.find((t) => t.id === targetId)?.project_id}
              targetId={targetId} onOpenRequest={openCapturedRequest}
              onSendToIntruder={sendCapturedToIntruder} />
          ) : <>
          {workspaceTab === "results" && <div className="webSectionTitle">
            <span>Recorded exchanges</span><h2>응답 이력과 비교</h2>
            <p>오른쪽 응답을 선택하고 기준 응답과 차이를 검토하세요.</p>
          </div>}
          {workspaceTab === "request" && <>
          {intruderSeed && !requestId && <div className="intruderPendingNotice">
            <b>SQLi 페이로드 {intruderSeed.values.length}개가 대기 중입니다.</b>
            <p>
              아래에서 요청을 완성하고 저장하면 Intruder 탭에 자동으로 채워집니다.
              테스트할 파라미터 값을 <code>{"{{position_1}}"}</code>으로 바꾸는 것도 잊지 마세요.
            </p>
          </div>}
          <details className="curlImport">
            <summary>cURL 붙여넣기로 가져오기</summary>
            <p>
              브라우저 개발자도구 Network 탭(또는 Burp)에서 요청 우클릭 → "Copy as cURL"로
              복사한 값을 붙여넣으면 Method·URL·Header·Cookie·Body를 채워줍니다.
            </p>
            <textarea value={curlInput} onChange={(e) => setCurlInput(e.target.value)}
              placeholder="curl 'http://...' -H '...' --data-raw '...'" rows={3} />
            <button type="button" disabled={!curlInput.trim()} onClick={importCurl}>가져오기</button>
          </details>
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
            <button disabled={!confirmed} onClick={send}>전송</button>
          </div>
          <div className="requestMeta">
            <input
              value={draft.name || ""}
              onChange={(e) => field("name", e.target.value)}
              placeholder="요청 이름"
            />
            <input
              value={draft.folder || ""}
              onChange={(e) => field("folder", e.target.value)}
              placeholder="폴더"
            />
            <input
              value={draft.tags || "[]"}
              onChange={(e) => field("tags", e.target.value)}
              placeholder='["tag"]'
            />
            <button onClick={save}>저장</button>
            <button disabled={!requestId} onClick={duplicate}>
              복제
            </button>
          </div>
          {error && <div className="webError">{error}</div>}
          <div className="requestGrid">
            <label>
              Query JSON
              <textarea
                value={draft.query || "{}"}
                onChange={(e) => field("query", e.target.value)}
              />
            </label>
            <label>
              Header JSON
              <textarea
                value={draft.headers || "{}"}
                onChange={(e) => field("headers", e.target.value)}
              />
            </label>
            <label>
              Cookie JSON
              <textarea
                value={draft.cookies || "{}"}
                onChange={(e) => field("cookies", e.target.value)}
              />
            </label>
            <label>
              Body
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
              TLS 검증
            </label>
            <label>
              <input
                type="checkbox"
                checked={draft.follow_redirects}
                onChange={(e) => field("follow_redirects", e.target.checked)}
              />{" "}
              Redirect 따라가기
            </label>
            <input
              value={draft.proxy || ""}
              onChange={(e) => field("proxy", e.target.value)}
              placeholder="선택 사항: Proxy URL"
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
              placeholder='변수 JSON, 예: {"id":"1"}'
            />
            <label>
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />{" "}
              허가된 요청
            </label>
          </div>
          </>}
          <div className="responsePanel">
            <div>
              <b>응답 Body</b>
              {exchangeId && (
                <a href={`/api/web/exchanges/${exchangeId}/body?download=true`}>
                  원본 Byte 다운로드
                </a>
              )}
            </div>
            <pre>{response}</pre>
          </div>
          </>}
        </section>
        <aside className="responseHistory">
          <h3>응답 이력</h3>
          <select
            value={compareId || ""}
            onChange={(e) => setCompareId(+e.target.value)}
          >
            <option value="">비교 기준</option>
            {exchanges.data
              ?.filter((item) => item.id !== exchangeId)
              .map((item) => (
                <option key={item.id} value={item.id}>
                  응답 #{item.id}
                </option>
              ))}
          </select>
          {comparison.data && (
            <div className="responseDiff">
              {comparison.data.changed
                ? `변경됨: ${Object.keys(comparison.data.changes).join(", ")}`
                : "관찰된 응답 변경 없음"}
            </div>
          )}
          {exchanges.isLoading && <LoadingState label="응답 이력을 불러오는 중" />}
          {exchanges.error && <ErrorState message={String(exchanges.error)} />}
          {!exchanges.isLoading && !exchanges.data?.length &&
            <EmptyState title="응답 이력이 없습니다" description="요청을 전송하면 여기에 기록됩니다." />}
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
