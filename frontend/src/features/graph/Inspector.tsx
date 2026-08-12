import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api";
import { DetachableTerminal } from "../../FloatingTerminal";
import SmartTerminalOutput from "../../SmartTerminalOutput";
import { parseLinkExtractResults } from "../../serviceIntel";
import { AddForm, color, DeepLink, EXECUTION_STATUS_LABEL, GLYPH, GraphNode,
  GraphRequestDraft, LINK_KIND_LABEL, LINK_KIND_ORDER, nodeMeta, nodeStatusReason,
  STATUS_LABEL, STATUS_ORDER, STATUS_REASON } from "./graphModel";
import { S } from "./graphStyles";
import { AddNodeForm } from "./graphLeaves";

export function Inspector(props: {
  node?: GraphNode; links?: DeepLink[]; busy: boolean;
  projectId?: number;
  executionContext?: { targetId: number; serviceId?: number } | null;
  onOpenRequest?: (draft: GraphRequestDraft) => void;
  onToggleHidden: (id: string, hidden: boolean) => void;
  onSetStatus: (id: string, status: string) => void;
  onSetDetails?: (id: string, details: { notes?: string; pinned?: boolean }) => void;
  onAddNode: (v: AddForm & { sourceId: string }) => void;
}) {
  const n = props.node;
  // node.label is now the catalog's human-readable name (e.g. "Responder
  // 리스너"), not the template id -- template-specific panels below key off
  // the id, which only survives in meta.tool.
  const tool = n ? (nodeMeta(n).tool as string | undefined) : undefined;
  const [adding, setAdding] = useState(false);
  const [notes, setNotes] = useState(n?.notes || "");
  useEffect(() => setNotes(n?.notes || ""), [n?.id, n?.notes]);
  const source = (() => {
    if (!n?.source_ref) return null;
    try {
      const ref = JSON.parse(n.source_ref);
      return Number.isInteger(ref.id) ? { kind: ref.kind as string, id: ref.id as number } : null;
    } catch { return null; }
  })();
  const executionId = source?.kind === "execution" ? source.id : null;
  const sessionId = source?.kind === "session" ? source.id : null;
  const executionOutput = useQuery({
    queryKey: ["executionOutput", executionId],
    enabled: executionId !== null,
    queryFn: () => api<{ stdout?: string; stderr?: string; status: string;
      error?: string; exit_code?: number | null }>(`/executions/${executionId}/output`),
  });
  const targets = useQuery({
    queryKey: ["graphLinkTargets"],
    enabled: (executionId !== null || sessionId !== null) && !!props.executionContext,
    queryFn: () => api<Array<{ id: number; project_id: number; ip: string; hostname?: string }>>("/targets"),
  });
  const services = useQuery({
    queryKey: ["graphLinkServices", props.executionContext?.targetId],
    enabled: executionId !== null && !!props.executionContext?.serviceId,
    queryFn: () => api<Array<{ id: number; port: number; name: string;
      product?: string; tls?: boolean }>>(
      `/targets/${props.executionContext!.targetId}/services`),
  });
  const [evidenceState, setEvidenceState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [revealedCapture, setRevealedCapture] = useState<string | null>(null);
  const [captureMessage, setCaptureMessage] = useState("");
  const responderCaptures = useQuery({
    queryKey: ["responderCaptures", props.executionContext?.targetId],
    enabled: sessionId !== null && tool === "responder-listener"
      && !!props.executionContext?.targetId,
    refetchInterval: 4000,
    queryFn: () => api<Array<{ label: string; username: string; value: string;
      cleartext: boolean; captured_at: string }>>(
      `/targets/${props.executionContext!.targetId}/responder-captures`),
  });
  const extractedLinks = parseLinkExtractResults(executionOutput.data?.stdout || "")
    .sort((a, b) => LINK_KIND_ORDER.indexOf(a.kind) - LINK_KIND_ORDER.indexOf(b.kind));
  const target = targets.data?.find((item) => item.id === props.executionContext?.targetId);
  const service = services.data?.find((item) => item.id === props.executionContext?.serviceId);
  const command = (() => {
    try { return JSON.parse(n?.meta || "{}").command || ""; } catch { return ""; }
  })();
  const base = target && service
    ? `${service.tls || /https|ssl/i.test(service.name) ? "https" : "http"}`
      + `://${target.hostname || target.ip}:${service.port}/`
    : "";
  const openInRequest = (url: string) => {
    if (!props.executionContext?.serviceId || !base || !target) return;
    const resolved = new URL(url, base).toString();
    localStorage.setItem("oscp-web-launch", JSON.stringify({
      targetId: props.executionContext.targetId,
      serviceId: props.executionContext.serviceId,
      url: resolved,
    }));
    props.onOpenRequest?.({ projectId: target.project_id,
      targetId: props.executionContext.targetId,
      serviceId: props.executionContext.serviceId, url: resolved });
  };
  const saveEvidence = async () => {
    if (executionId === null || !executionOutput.data?.stdout) return;
    setEvidenceState("saving");
    try {
      await api(`/executions/${executionId}/derive`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          content: executionOutput.data.stdout,
          filename: `link-extract-${executionId}.txt`,
        }),
      });
      setEvidenceState("saved");
    } catch { setEvidenceState("error"); }
  };
  const saveResponderCapture = async (capture: {
    label: string; username: string; value: string; cleartext: boolean;
  }) => {
    if (!target || !props.executionContext) return;
    setCaptureMessage("저장 중…");
    try {
      await api("/runbooks/credentials", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ project_id: target.project_id,
          target_id: props.executionContext.targetId, username: capture.username,
          secret: capture.value, secret_kind: capture.cleartext ? "password" : "hash",
          secret_hint: capture.cleartext ? "Responder 평문 캡처" : "Responder NTLMv2-SSP 캡처",
          source_kind: "responder", source_detail: capture.label, service_names: [] }),
      });
      setCaptureMessage(`${capture.username} 저장 완료`);
    } catch (reason) {
      setCaptureMessage(`저장 실패: ${reason instanceof Error ? reason.message : String(reason)}`);
    }
  };
  if (!n)
    return <aside style={S.inspector}>
      <div style={{ color: "#6b6b76", fontSize: 13 }}>노드를 선택하세요.</div>
    </aside>;
  return (
    <aside style={S.inspector}>
      <div style={S.inspectorTitle}><h3 style={{ margin: 0, fontSize: 15 }}>{n.label}</h3>
        <button title={n.pinned ? "북마크 해제" : "북마크"}
          onClick={() => props.onSetDetails?.(n.id, { pinned: !n.pinned })}>
          {n.pinned ? "★" : "☆"}</button></div>
      <div style={{ color: "#6b6b76", fontSize: 12 }}>
        {GLYPH[n.type]} {n.type}
        {n.objective && <span style={{ color: "#f5c518" }}> · 🎯 목표</span>}
        {n.hidden && <span style={{ color: "#6b6b76" }}> · 숨김</span>}
      </div>
      <div style={{ marginTop: 14 }}>
        <div style={{ color: "#9a9aa6", fontSize: 11, marginBottom: 6 }}>상태</div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {STATUS_ORDER.map((s) => (
            <button key={s} onClick={() => props.onSetStatus(n.id, s)} style={{
              fontSize: 11, padding: "4px 8px", borderRadius: 6, cursor: "pointer",
              border: `1px solid ${n.status === s ? color(s) : "#2a2a34"}`,
              background: n.status === s ? `${color(s)}22` : "transparent",
              color: n.status === s ? color(s) : "#9a9aa6",
            }}>{s === n.status ? nodeStatusReason(n) : STATUS_REASON[s] ?? s}</button>
          ))}
        </div>
      </div>
      <section style={S.nodeNotes}>
        <div><span>작업 메모</span><button disabled={notes === (n.notes || "")}
          onClick={() => props.onSetDetails?.(n.id, { notes })}>저장</button></div>
        <textarea value={notes} onChange={(event) => setNotes(event.target.value)}
          placeholder="확인한 내용, 실패 원인, 다음에 볼 항목을 기록하세요." />
      </section>
      {executionId !== null && <DetachableTerminal id={`graph-execution-${executionId}`}
        label={`${n.label} 실행 결과`}
        commandContext={target && props.executionContext ? {
          targetId: props.executionContext.targetId,
          targetIp: target.ip,
          serviceId: props.executionContext.serviceId,
        } : undefined}>
        <section style={S.executionResults} aria-label="실행 결과">
        <div style={S.terminalTitlebar} data-terminal-drag-handle
          title="드래그하여 터미널 분리">
          <span style={S.terminalDots}>
            <i style={{ ...S.terminalDot, background: "#ff5f57" }} />
            <i style={{ ...S.terminalDot, background: "#febc2e" }} />
            <i style={{ ...S.terminalDot, background: "#28c840" }} />
          </span>
          <span style={S.terminalTitle}>
            {target ? (target.hostname || target.ip) : "localhost"}
            {service ? `:${service.port}` : ""} — {n.label}
          </span>
          <span style={{ font: "10px ui-monospace,monospace", color: "#7fae8f", flexShrink: 0 }}>
            {EXECUTION_STATUS_LABEL[executionOutput.data?.status || ""]
              || STATUS_LABEL[n.status] || executionOutput.data?.status || n.status}
            {executionOutput.data?.exit_code == null ? "" : ` · exit ${executionOutput.data.exit_code}`}
          </span>
        </div>
        <div style={S.terminalBody}>
          {command && <div style={S.terminalPromptLine}>
            <span style={S.terminalPrompt}>$</span>{command}
          </div>}
          {executionOutput.isLoading ? <div style={S.resultMessage}>결과 불러오는 중…</div>
            : executionOutput.isError ? <div style={S.resultError}>실행 결과를 불러오지 못했습니다.</div>
            : <>
              {executionOutput.data?.error && <div style={S.resultError}>{executionOutput.data.error}</div>}
              {executionOutput.data?.stdout && <details open={n.label !== "http-link-extract"}>
                <summary style={S.terminalComment}># stdout</summary>
                <pre style={S.terminalOutput}><SmartTerminalOutput
                  output={executionOutput.data.stdout} context={{projectId: props.projectId,
                    targetId: props.executionContext?.targetId, targetIp: target?.ip,
                    serviceId: props.executionContext?.serviceId}} /></pre>
              </details>}
              {executionOutput.data?.stderr && <details open>
                <summary style={S.terminalComment}># stderr</summary>
                <pre style={S.terminalOutputError}>{executionOutput.data.stderr}</pre>
              </details>}
              {!executionOutput.data?.stdout && !executionOutput.data?.stderr
                && !executionOutput.data?.error && <div style={S.resultMessage}>저장된 출력이 없습니다.</div>}
            </>}
        </div>
        </section>
      </DetachableTerminal>}
      {executionId !== null && tool === "http-link-extract" && (
        <section style={S.executionResults} aria-label="링크 추출 결과">
          <div style={S.executionResultsHead}>
            <div><strong>발견된 링크</strong> <span>{extractedLinks.length}개</span></div>
            {!!extractedLinks.length && (
              <button style={S.resultAction} disabled={evidenceState === "saving"}
                onClick={() => void saveEvidence()}>
                {evidenceState === "saving" ? "저장 중…" : "Evidence로 저장"}
              </button>
            )}
          </div>
          {evidenceState === "saved" && <div style={S.resultNotice}>Evidence로 저장됨</div>}
          {evidenceState === "error" && <div style={S.resultError}>Evidence 저장 실패</div>}
          {executionOutput.isLoading ? (
            <div style={S.resultMessage}>결과 불러오는 중…</div>
          ) : executionOutput.isError ? (
            <div style={S.resultMessage}>실행 결과를 불러오지 못했습니다.</div>
          ) : extractedLinks.length ? (
            <div style={S.linkList}>
              <div style={{ ...S.linkRow, ...S.linkHeader }}>
                <span>링크</span><span>유형</span><span />
              </div>
              {extractedLinks.map((item) => (
                <div key={`${item.kind}:${item.url}`} style={S.linkRow}>
                  <code style={S.linkCode}>{item.url}</code>
                  <span style={S.linkKind}>{LINK_KIND_LABEL[item.kind] || item.kind}</span>
                  <span>{(item.kind === "page" || item.kind === "absolute") && base && (
                    <button style={S.rowAction} onClick={() => openInRequest(item.url)}>
                      Request 탭에 채우기
                    </button>
                  )}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={S.resultMessage}>이 실행에서 찾은 링크가 없습니다.</div>
          )}
        </section>
      )}
      {sessionId !== null && tool === "responder-listener" && (
        <section style={S.executionResults} aria-label="Responder 캡처 결과">
          <div style={S.executionResultsHead}>
            <div><strong>캡처된 자격증명</strong>{" "}
              <span>{responderCaptures.data?.length || 0}개</span></div>
            <span style={{ color: "#59f59a" }}>LIVE · 4s</span>
          </div>
          {captureMessage && <div style={S.resultNotice}>{captureMessage}</div>}
          {responderCaptures.isLoading ? <div style={S.resultMessage}>Responder 로그 확인 중…</div>
            : responderCaptures.isError ? <div style={S.resultError}>캡처 로그를 읽지 못했습니다.</div>
            : responderCaptures.data?.length ? <div style={S.captureList}>
              {responderCaptures.data.map((capture) => {
                const key = `${capture.label}:${capture.username}`;
                const shown = revealedCapture === key;
                return <article key={key} style={S.captureCard}>
                  <div style={S.captureHead}><b>{capture.username}</b>
                    <span>{capture.cleartext ? "CLEARTEXT" : "NETNTLMv2"}</span></div>
                  <div style={S.captureMeta}>{capture.label} · {new Date(capture.captured_at).toLocaleString()}</div>
                  <code style={S.captureValue}>{shown ? capture.value : "••••••••••••••••••••••••"}</code>
                  <div style={S.captureActions}>
                    <button onClick={() => setRevealedCapture(shown ? null : key)}>
                      {shown ? "숨기기" : "해시 보기"}</button>
                    <button onClick={() => void navigator.clipboard.writeText(capture.value)}>복사</button>
                    <button onClick={() => void saveResponderCapture(capture)}>Credential 저장</button>
                  </div>
                </article>;
              })}
            </div> : <div style={S.resultMessage}>
              아직 이 대상에서 캡처된 자격증명이 없습니다. 새 캡처는 자동으로 표시됩니다.
            </div>}
        </section>
      )}
      {props.links?.map((link) => (
        <button key={link.label} onClick={link.open} style={S.openBtn}>{link.label}</button>
      ))}
      {adding ? (
        <AddNodeForm source={n} busy={props.busy} onCancel={() => setAdding(false)}
          onSubmit={(v) => { props.onAddNode({ sourceId: n.id, ...v }); setAdding(false); }} />
      ) : (
        <button onClick={() => setAdding(true)} style={S.openBtn}>＋ 연결 노드 추가</button>
      )}
      {n.type !== "project-root" && (
        <button onClick={() => props.onToggleHidden(n.id, !n.hidden)} style={S.hideBtn}>
          {n.hidden ? "복원" : "그래프에서 숨기기"}
        </button>
      )}
    </aside>
  );
}
