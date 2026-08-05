import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import type { SavedRequest } from "./WebWorkspace";

type ProxyStatus = {
  running: boolean;
  port?: number;
  target_ip?: string;
  project_id?: number;
  target_id?: number;
  stderr_tail: string[];
};

const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch("/api" + path, init);
  if (!response.ok) throw new Error((await response.json()).detail || response.statusText);
  return response.status === 204 ? (null as T) : response.json();
};

export default function ProxyPanel({ projectId, targetId, onOpenRequest, onSendToIntruder }: {
  projectId?: number; targetId?: number;
  onOpenRequest: (request: SavedRequest) => void;
  onSendToIntruder: (request: SavedRequest) => void;
}) {
  const qc = useQueryClient();
  const [port, setPort] = useState(8081);
  const [error, setError] = useState("");
  const status = useQuery({
    queryKey: ["proxyStatus"],
    queryFn: () => api<ProxyStatus>("/web/proxy/status"),
    refetchInterval: 2000,
  });
  const running = !!status.data?.running;
  const captured = useQuery({
    queryKey: ["proxyCaptures", targetId],
    queryFn: () => api<SavedRequest[]>(`/web/proxy/captures?target_id=${targetId}`),
    enabled: !!targetId,
    refetchInterval: running ? 2000 : false,
  });
  const start = async () => {
    if (!projectId || !targetId) return;
    setError("");
    try {
      await api("/web/proxy/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ project_id: projectId, target_id: targetId, port }),
      });
      qc.invalidateQueries({ queryKey: ["proxyStatus"] });
    } catch (e) {
      setError(String(e));
    }
  };
  const stop = async () => {
    setError("");
    try {
      await api("/web/proxy/stop", { method: "POST" });
      qc.invalidateQueries({ queryKey: ["proxyStatus"] });
    } catch (e) {
      setError(String(e));
    }
  };
  return (
    <section className="proxyPanel">
      <div className="webSectionTitle">
        <span>Proxy capture</span>
        <h2>브라우저 트래픽 캡처</h2>
        <p>
          브라우저 프록시 설정을 아래 주소로 맞추면 대상 IP로 가는 요청만 자동 저장됩니다.
          다른 사이트 트래픽은 그대로 통과만 되고 기록되지 않습니다. 로컬(127.0.0.1)에서만 동작합니다.
        </p>
      </div>
      {error && <div className="webError">{error}</div>}
      {(!projectId || !targetId) &&
        <div className="webError">대상을 먼저 선택하세요.</div>}
      <div className="proxyControls">
        <label>포트
          <input type="number" min="1024" max="65535" value={port} disabled={running}
            onChange={(e) => setPort(+e.target.value)} />
        </label>
        {running
          ? <button onClick={stop}>중지</button>
          : <button disabled={!projectId || !targetId} onClick={start}>시작</button>}
        <span className={running ? "proxyStatus isRunning" : "proxyStatus"}>
          {running ? `실행 중 · 127.0.0.1:${status.data?.port}` : "중지됨"}
        </span>
      </div>
      {running && <div className="proxySetup">
        <p>브라우저 프록시 설정: <code>127.0.0.1:{status.data?.port}</code> (HTTP·HTTPS 모두)</p>
        <a href="/api/web/proxy/ca-cert">CA 인증서 다운로드</a>
        <details>
          <summary>Firefox에 인증서 신뢰 설치하는 방법</summary>
          <ol>
            <li><code>about:preferences#privacy</code>로 이동</li>
            <li>아래로 스크롤 → 인증서 → "인증서 보기"</li>
            <li>"기관" 탭 → "가져오기" → 방금 다운로드한 mitmproxy-ca-cert.pem 선택</li>
            <li>"이 CA가 웹사이트를 식별하도록 신뢰함" 체크 후 확인</li>
          </ol>
        </details>
      </div>}
      {!!status.data?.stderr_tail?.length &&
        <pre className="proxyStderr">{status.data.stderr_tail.join("\n")}</pre>}
      <div className="proxyCaptures">
        <b>캡처된 요청 · {captured.data?.length || 0}개</b>
        {!captured.data?.length &&
          <div className="empty">아직 캡처된 요청이 없습니다.</div>}
        {captured.data?.map((request) => (
          <div className="proxyCaptureRow" key={request.id}>
            <code>{request.method} {request.url}</code>
            {request.cloud_fingerprint ? (
              <em className="cloudFingerprint" title={
                [request.cloud_fingerprint.meaning, request.cloud_fingerprint.next_step]
                  .filter(Boolean).join(" ")
              }>
                ☁️ {request.cloud_fingerprint.provider}
                {request.cloud_fingerprint.error_code
                  ? ` · ${request.cloud_fingerprint.error_code}` : ""}
              </em>
            ) : request.has_response ? (
              <em className="cloudFingerprintQuiet">확인됨 · 클라우드 스토리지 아님</em>
            ) : (
              <em className="cloudFingerprintPending">응답 대기 중</em>
            )}
            <div className="proxyCaptureActions">
              <button onClick={() => onOpenRequest(request)}>Request로 열기</button>
              <button onClick={() => onSendToIntruder(request)}>Intruder로</button>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
