import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api";
import { DetachableTerminal } from "../../FloatingTerminal";
import SmartTerminalOutput from "../../SmartTerminalOutput";
import InteractiveTerminal from "../../InteractiveTerminal";
import XtermOutput from "../../XtermOutput";
import { parseLinkExtractResults, parseMysqlProbeSuccess } from "../../serviceIntel";
import { buildFileTree, FileTreeView, parseTaggedTreeLines } from "../../fileTree";
import FileContentModal from "../../FileContentModal";
import NetexecOutcome, { type NetexecProtocol } from "../../NetexecOutcome";
import { impacketAuthArgs, shellQuote } from "../../enumerationModel";
import { AddForm, color, DeepLink, EXECUTION_STATUS_LABEL, GLYPH, GraphNode,
  GraphRequestDraft, LINK_KIND_LABEL, LINK_KIND_ORDER, nodeMeta, nodeStatusReason,
  STATUS_LABEL, STATUS_ORDER, STATUS_REASON } from "./graphModel";
import { S } from "./graphStyles";
import { AddNodeForm } from "./graphLeaves";

type StoredCredential = {
  id: number; username: string; domain?: string; secret: string; secret_kind: string;
  secret_hint?: string; source_kind?: string; source_detail?: string;
  source_execution_kind?: string;
};

// Shared shape for every "does this protocol allow unauthenticated (or
// just-confirmed) access" check -- mongodb/snmp/mysql-probe/webdav/
// ldap-anonymous/svn all follow the same pattern App.tsx's own auto-run
// already established: check succeeds -> a richer follow-up command
// already ran against the same target -- this just surfaces that result
// (and a connect action, where one genuinely exists) instead of a plain
// "성공" label with nothing to act on.
function UnauthAccessResult({label, connectLabel, onConnect, treeLabel, tree}: {
  label: string; connectLabel?: string; onConnect?: () => void;
  treeLabel?: string; tree?: {status: string; stdout: string};
}) {
  return <section style={S.netexecNodeResult} aria-label={`${label} 결과`}>
    <div style={S.netexecNodeResultHead}>
      <span>{label}</span>
      <strong>확인됨</strong>
    </div>
    {onConnect && <div style={{ padding: "0 12px 12px" }}>
      <button style={S.resultAction} onClick={onConnect}>{connectLabel}</button>
    </div>}
    {treeLabel && <div style={S.netexecTree}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 8, padding: "9px 12px" }}>
        <b>{treeLabel}</b>
      </div>
      {!tree ? <div style={S.resultMessage}>자동 조회 중…</div>
        : <pre style={S.terminalOutput}>{tree.stdout || "(빈 결과)"}</pre>}
    </div>}
  </section>;
}

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
  const credentialId = source?.kind === "credential" ? source.id : null;
  const findingId = source?.kind === "finding" ? source.id : null;
  const findingQuery = useQuery({
    queryKey: ["graphFinding", findingId],
    enabled: findingId !== null,
    queryFn: () => api<{ evidence: Array<{ id: number; evidence_id: number; title: string;
      kind: string; is_primary: boolean }> }>(`/findings/${findingId}`),
  });
  // Only findings promoted from a file-tree drag (promote-file always sets
  // this exact kind+is_primary combination) get their content shown here --
  // manually-created findings' screenshots/notes already have their own
  // views elsewhere and would just error against the text-only preview.
  const findingFileEvidenceId = findingQuery.data?.evidence.find(
    (item) => item.is_primary && item.kind === "command_output")?.evidence_id;
  const findingFilePreview = useQuery({
    queryKey: ["graphFindingFilePreview", findingFileEvidenceId],
    enabled: findingFileEvidenceId !== undefined,
    queryFn: () => api<{ content: string; truncated: boolean }>(
      `/evidence/${findingFileEvidenceId}/preview`),
  });
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
      product?: string; version?: string; extra_info?: string; tls?: boolean }>>(
      `/targets/${props.executionContext!.targetId}/services`),
  });
  const [evidenceState, setEvidenceState] = useState<"idle" | "saving" | "saved" | "error">("idle");
  const [revealedCapture, setRevealedCapture] = useState<string | null>(null);
  const [credentialRevealed, setCredentialRevealed] = useState(false);
  useEffect(() => setCredentialRevealed(false), [credentialId]);
  const [captureMessage, setCaptureMessage] = useState("");
  const [retrySession, setRetrySession] = useState<{id: number; command: string} | null>(null);
  const [manualSession, setManualSession] = useState<
    {id: number; title: string; initialInput?: string} | null
  >(null);
  const [openFilePath, setOpenFilePath] = useState<string | null>(null);
  const [retryError, setRetryError] = useState("");
  const sessionQuery = useQuery({
    queryKey: ["graphInteractiveSession", sessionId],
    enabled: sessionId !== null,
    refetchInterval: 3000,
    queryFn: async () => {
      const rows = await api<Array<{id: number; command: string; status: string}>>(
        `/interactive-sessions?target_id=${props.executionContext?.targetId || ""}`);
      return rows.find((item) => item.id === sessionId) || null;
    },
  });
  const sessionLog = useQuery({
    queryKey: ["graphInteractiveSessionLog", sessionId],
    enabled: sessionId !== null && tool === "responder-listener",
    refetchInterval: sessionQuery.data?.status === "running" ? 1500 : false,
    queryFn: async () => {
      const response = await fetch(`/api/interactive-sessions/${sessionId}/log`);
      if (!response.ok) return "세션 로그가 아직 생성되지 않았습니다.";
      return response.text();
    },
  });
  const responderCaptures = useQuery({
    queryKey: ["responderCaptures", props.executionContext?.targetId],
    enabled: sessionId !== null && tool === "responder-listener"
      && !!props.executionContext?.targetId,
    refetchInterval: 4000,
    queryFn: () => api<Array<{ label: string; username: string; value: string;
      cleartext: boolean; captured_at: string }>>(
      `/targets/${props.executionContext!.targetId}/responder-captures`),
  });
  // A manual FTP session has no structured "this file was downloaded" API
  // call the way the post-exploitation file tree does -- the client's own
  // transcript (already logged) is the only record, so this reads that log
  // back rather than watching the PTY live.
  const ftpDownloads = useQuery({
    queryKey: ["graphFtpDownloads", sessionId],
    enabled: sessionId !== null,
    refetchInterval: sessionQuery.data?.status === "running" ? 3000 : false,
    queryFn: () => api<{ files: Array<{ filename: string; size: number }> }>(
      `/interactive-sessions/${sessionId}/ftp-downloads`),
  });
  const [promotedDownloads, setPromotedDownloads] = useState<Set<string>>(new Set());
  const queryClient = useQueryClient();
  const promoteDownload = async (filename: string) => {
    if (sessionId === null) return;
    setCaptureMessage("");
    try {
      await api(`/interactive-sessions/${sessionId}/promote-download`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({filename, graph_node_id: n?.id}),
      });
      setPromotedDownloads((current) => new Set(current).add(filename));
      setCaptureMessage(`${filename} 그래프에 남겼습니다`);
      void queryClient.invalidateQueries({queryKey: ["graph"]});
    } catch (reason) {
      setCaptureMessage(`실패: ${reason instanceof Error ? reason.message : String(reason)}`);
    }
  };
  // A promoted zip was previously a dead end past its own "download" link --
  // this lets an entry inside it become its own graph node too, the same
  // way promote-download turns a file sitting in a session's cwd into one.
  // Only ever reads bytes back out of the archive server-side (never
  // extracts to an entry-controlled path), so this is just a list-and-pick
  // UI over an endpoint that's already zip-slip safe on its own.
  const [openArchiveId, setOpenArchiveId] = useState<number | null>(null);
  const archiveQuery = useQuery({
    queryKey: ["evidenceArchive", openArchiveId],
    enabled: openArchiveId !== null,
    queryFn: () => api<{ entries: Array<{ name: string; size: number; encrypted: boolean }> }>(
      `/evidence/${openArchiveId}/archive`),
  });
  const [extractedEntries, setExtractedEntries] = useState<Set<string>>(new Set());
  const [archiveMessage, setArchiveMessage] = useState("");
  useEffect(() => { setOpenArchiveId(null); setArchiveMessage(""); }, [n?.id]);
  const extractEntry = async (evidenceId: number, entryName: string) => {
    setArchiveMessage("");
    try {
      await api(`/evidence/${evidenceId}/extract`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({entry: entryName}),
      });
      setExtractedEntries((current) => new Set(current).add(`${evidenceId}:${entryName}`));
      setArchiveMessage(`${entryName} 그래프에 남겼습니다`);
      void queryClient.invalidateQueries({queryKey: ["graph"]});
    } catch (reason) {
      setArchiveMessage(`실패: ${reason instanceof Error ? reason.message : String(reason)}`);
    }
  };
  const credentialQuery = useQuery({
    queryKey: ["graphCredential", props.projectId, credentialId],
    enabled: credentialId !== null && !!props.projectId,
    queryFn: async () => {
      const rows = await api<StoredCredential[]>(
        `/runbooks/credentials?project_id=${props.projectId}`);
      return rows.find((item) => item.id === credentialId) || null;
    },
  });
  // Every NetExec single-account check template renders the exact same
  // "nxc {protocol} {host} --port {port} -u {username} -p {password}" shape
  // (services.yaml), so the protocol and the account it was tried with are
  // both recoverable straight from the command string this node already
  // has -- no separate credStore needed the way App.tsx's copy of this same
  // panel has, since this view has no per-workspace credential input of its
  // own to draw from.
  const netexecProtocol = /^(smb|ssh|winrm|rdp|mssql|ldap)-credential-check-netexec$/
    .exec(tool || "")?.[1] as NetexecProtocol | undefined;
  const isNetexecCheck = !!netexecProtocol;
  const isRedisUnauthCheck = tool === "redis-unauthenticated-info";
  // Every "does this protocol allow unauthenticated access" check already
  // auto-triggers a richer follow-up command against this same target
  // (App.tsx's autoRun*Tree functions) once it succeeds -- this just reads
  // that follow-up's own result back by template id + service, instead of
  // re-running anything itself.
  const unauthChecks = useQuery({
    queryKey: ["graphUnauthCheckExecutions", props.executionContext?.targetId],
    enabled: !!props.executionContext?.targetId,
    queryFn: () => api<Array<{ id: number; template_id: string; service_id: number | null;
      status: string; stdout: string }>>(
      `/executions?target_id=${props.executionContext!.targetId}`),
  });
  const latestExecutionFor = (templateId: string) => unauthChecks.data
    ?.filter((item) => item.template_id === templateId && item.status === "completed"
      && (!props.executionContext?.serviceId || item.service_id === props.executionContext.serviceId))
    .sort((a, b) => b.id - a.id)[0];
  const isMongoCheck = tool === "mongodb-info";
  const mongoSuccess = /mongodb-info:/i.test(executionOutput.data?.stdout || "");
  const isSnmpCheck = tool === "snmp-info";
  const snmpSuccess = /snmp-info:/i.test(executionOutput.data?.stdout || "");
  const isMysqlProbeCheck = tool === "mysql-credential-probe";
  const mysqlProbe = parseMysqlProbeSuccess(executionOutput.data?.stdout || "");
  const isWebdavCheck = tool === "http-webdav-detect";
  const webdavSuccess = /PROPFIND/i.test(executionOutput.data?.stdout || "");
  const isLdapAnonCheck = tool === "ldap-anonymous-users";
  const ldapAnonSuccess = /^\[\+\]/im.test(executionOutput.data?.stdout || "");
  const isSvnCheck = tool === "svn-wcdb-check";
  const svnSuccess = /^HTTP\/[\d.]+ 200/im.test(executionOutput.data?.stdout || "");
  // service-version's own catalog description already promises this: "관찰된
  // 값을 이 서비스에 자동 저장합니다" -- and the backend genuinely does that
  // (executor.py's update_execution_observations, on every -oX completion).
  // What was missing was ever showing that here -- without it this panel is
  // just raw nmap stdout the operator has to parse by hand to learn what the
  // service row already has.
  const isServiceVersionCheck = tool === "service-version" || tool === "service-version-udp";
  const fileTreeRuns = useQuery({
    queryKey: ["graphFileTreeRuns", props.executionContext?.targetId],
    enabled: isNetexecCheck && !!props.executionContext?.targetId,
    queryFn: () => api<Array<{ id: number; command_id: string; category: string;
      status: string; created_at: string }>>(
      `/post-exploitation?target_id=${props.executionContext!.targetId}`),
  });
  const latestFileTree = fileTreeRuns.data?.find((run) =>
    run.category === "file_tree" && run.status === "completed");
  const fileTreeOutput = useQuery({
    queryKey: ["graphFileTreeOutput", latestFileTree?.id],
    enabled: !!latestFileTree,
    queryFn: () => api<{ stdout: string; stderr: string }>(
      `/post-exploitation/${latestFileTree!.id}/output`),
  });
  const extractedLinks = parseLinkExtractResults(executionOutput.data?.stdout || "")
    .sort((a, b) => LINK_KIND_ORDER.indexOf(a.kind) - LINK_KIND_ORDER.indexOf(b.kind));
  const target = targets.data?.find((item) => item.id === props.executionContext?.targetId);
  const service = services.data?.find((item) => item.id === props.executionContext?.serviceId);
  const command = (() => {
    try { return JSON.parse(n?.meta || "{}").command || ""; } catch { return ""; }
  })();
  const netexecUsername = /-u\s+(\S+)/.exec(command)?.[1] || "";
  const netexecPassword = /-p\s+(\S+)/.exec(command)?.[1] || "";
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
  const retry = async () => {
    if (sessionId === null) return;
    setRetryError("");
    try {
      const next = await api<{id: number; command: string}>(
        `/interactive-sessions/${sessionId}/retry`, {method: "POST"});
      setRetrySession(next);
    } catch (reason) {
      setRetryError(reason instanceof Error ? reason.message : String(reason));
    }
  };
  // Mirrors App.tsx's openEvilWinrmShell: a plaintext password never touches
  // argv or the sessions table (the backend rejects -p/-H outright), so it
  // gets typed into evil-winrm's own interactive prompt instead. A hash has
  // no such prompt to type into, so it has to ride in argv via -H -- typed
  // into a bare shell for the user to review and press Enter on themselves.
  const openEvilWinrm = async () => {
    if (!target || !props.executionContext) return;
    const userMatch = /-u\s+(\S+)/.exec(command);
    const hashMatch = /-H\s+(\S+)/.exec(command);
    const passMatch = /-p\s+(\S+)/.exec(command);
    if (!userMatch || (!hashMatch && !passMatch)) return;
    const base = `evil-winrm -i ${target.ip} -u ${userMatch[1]}`;
    const body: Record<string, unknown> = {
      target_id: props.executionContext.targetId,
      service_id: props.executionContext.serviceId || null,
    };
    if (!hashMatch) body.command = base;
    const session = await api<{id: number}>("/interactive-sessions/manual", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
    });
    setManualSession(hashMatch
      ? {id: session.id, title: `${base} -H … · 검토 후 Enter`,
        initialInput: `${base} -H ${hashMatch[1]}`}
      : {id: session.id, title: base, initialInput: `${passMatch![1]}\r`});
  };
  // redis-unauthenticated-info already proved INFO runs with no AUTH -- one
  // click opens the same interactive client a manual "redis-client" catalog
  // run would, instead of the operator having to go find it themselves.
  const openManualSession = async (cmd: string, title?: string, initialInput?: string) => {
    if (!props.executionContext) return;
    const session = await api<{id: number}>("/interactive-sessions/manual", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        target_id: props.executionContext.targetId,
        service_id: props.executionContext.serviceId || null,
        command: cmd,
      }),
    });
    setManualSession({id: session.id, title: title || cmd, initialInput});
  };
  const openRedisShell = async () => {
    if (!target) return;
    await openManualSession(`redis-cli -h ${target.ip} -p ${service?.port || 6379}`);
  };
  const openMongoShell = async () => {
    if (!target) return;
    await openManualSession(`mongosh --host ${target.ip} --port ${service?.port || 27017}`);
  };
  // mysql-client's trailing bare -p prompts interactively (same pattern as
  // evil-winrm's plaintext path) -- the probe's own recovered password is
  // typed into that prompt rather than riding in argv.
  const openMysqlProbeShell = async () => {
    if (!target || !mysqlProbe) return;
    await openManualSession(
      `mysql -h ${target.ip} -P ${service?.port || 3306} -u ${mysqlProbe.username} --skip-ssl -p`,
      undefined, `${mysqlProbe.password}\r`);
  };
  // Same shape as App.tsx's own copy of each of these (openSshShell,
  // openMssqlShell, openPsexecShell, openLateralShell, copyXfreerdpCommand,
  // openHashcatShell, runLookupsid, runMssqlRidBrute, captureEvidence,
  // promoteToFinding) -- this view has no credStore of its own, so username/
  // password come from the check command itself (see netexecUsername/
  // netexecPassword above) rather than a separately-typed form field.
  const openSsh = async () => {
    if (!target || !service || !netexecUsername) return;
    await openManualSession(`ssh ${shellQuote(`${netexecUsername}@${target.ip}`)} -p ${service.port}`);
  };
  const openMssql = async () => {
    if (!target || !service || !netexecUsername) return;
    const auth = impacketAuthArgs("", netexecUsername, netexecPassword, target.ip);
    await openManualSession(`impacket-mssqlclient ${auth} -port ${service.port}`);
  };
  const openPsexec = async () => {
    if (!target || !netexecUsername) return;
    const auth = impacketAuthArgs("", netexecUsername, netexecPassword, target.ip);
    await openManualSession(`impacket-psexec ${auth}`);
  };
  const openLateral = async (kind: "wmiexec" | "smbexec" | "atexec") => {
    if (!target || !netexecUsername) return;
    const auth = impacketAuthArgs("", netexecUsername, netexecPassword, target.ip);
    await openManualSession(`impacket-${kind} ${auth}`);
  };
  const copyRdp = async () => {
    if (!target || !netexecUsername) return;
    await navigator.clipboard.writeText(`xfreerdp /v:${target.ip} /u:${shellQuote(netexecUsername)}` +
      ` /p:${shellQuote(netexecPassword)} /cert:ignore`);
    setCaptureMessage("xfreerdp 명령을 클립보드로 복사했습니다 — RDP는 GUI라 별도 터미널에서 붙여넣어 실행하세요");
  };
  const openHashcat = () => {
    if (!props.executionContext) return;
    localStorage.setItem("oscp-workspace-hash-target", String(props.executionContext.targetId));
    localStorage.setItem("oscp-workspace-hash-mode", "kerberoast");
    location.hash = "hash-cracking";
  };
  // lookupsid/rid-brute are recon follow-ups, not a "connect" action, so
  // unlike the shell-opening actions above this only has to fire the
  // execution and let the graph's own auto-refresh pick up the new
  // technique node -- no need to duplicate App.tsx's live-output tracking
  // (runStates/EventSource) here just for this.
  const runFollowUpExecution = async (
    templateId: string, variables: Record<string, string>, label: string, targetLevel: boolean,
  ) => {
    if (!props.executionContext) return;
    try {
      const e = await api<{id: number}>("/executions", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          target_id: props.executionContext.targetId,
          service_id: targetLevel ? null : (props.executionContext.serviceId || null),
          template_id: templateId, variables, run_as_root: false,
          output_filename: "", command_override: null,
        }),
      });
      dispatchEvent(new CustomEvent("oscp-graph-refresh"));
      setCaptureMessage(`${label} 실행 요청됨 (#${e.id}) — 그래프에서 곧 새 노드로 보입니다`);
    } catch (reason) {
      setCaptureMessage(`${label} 실행 실패: ${reason instanceof Error ? reason.message : String(reason)}`);
    }
  };
  const openLookupsid = () => {
    if (!netexecUsername) return;
    void runFollowUpExecution("ad-lookupsid-impacket",
      {username: netexecUsername, password: netexecPassword, domain: "WORKGROUP"},
      "SID 순환 사용자 열거", true);
  };
  const openMssqlRidBrute = () => {
    if (!netexecUsername) return;
    void runFollowUpExecution("mssql-rid-brute-netexec",
      {username: netexecUsername, password: netexecPassword}, "RID 순환 사용자 열거", false);
  };
  const netexecCaptureEvidence = async (
    execution: {id: number; stdout?: string; stderr?: string}, title: string,
  ): Promise<number | undefined> => {
    if (!props.projectId || !props.executionContext) return undefined;
    setCaptureMessage("");
    try {
      const body = `$ ${command}\n\n${execution.stdout || ""}` +
        `${execution.stderr ? `\n[stderr]\n${execution.stderr}` : ""}`;
      const data = new FormData();
      data.append("project_id", String(props.projectId));
      data.append("target_id", String(props.executionContext.targetId));
      if (props.executionContext.serviceId)
        data.append("service_id", String(props.executionContext.serviceId));
      data.append("title", title);
      data.append("description", `자동 캡처 · ${new Date().toLocaleString()}`);
      data.append("kind", "command_output");
      data.append("source_type", "command_output");
      data.append("source_id", String(execution.id));
      data.append("sensitivity", "normal");
      data.append("file", new File([body], `execution-${execution.id}.txt`, {type: "text/plain"}));
      const response = await fetch("/api/evidence/upload", {method: "POST", body: data});
      const created = await response.json();
      if (!response.ok) throw new Error(created.detail || response.statusText);
      setCaptureMessage(`Evidence로 저장됨: ${title}`);
      return created.id as number;
    } catch (reason) {
      setCaptureMessage(`Evidence 저장 실패: ${reason instanceof Error ? reason.message : String(reason)}`);
      return undefined;
    }
  };
  const netexecPromoteFinding = async (
    execution: {id: number; stdout?: string; stderr?: string}, title: string, reproduction: string,
  ) => {
    const evidenceId = await netexecCaptureEvidence(execution, title);
    if (!evidenceId || !props.projectId || !props.executionContext) return;
    try {
      await api("/findings", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          project_id: props.projectId, target_id: props.executionContext.targetId,
          service_id: props.executionContext.serviceId,
          title, status: "Draft", reproduction_steps: reproduction,
          evidence: [{evidence_id: evidenceId, is_primary: true}],
        }),
      });
      setCaptureMessage(`Finding(Draft)으로 승격됨: ${title}`);
    } catch (reason) {
      setCaptureMessage(`Finding 승격 실패: ${reason instanceof Error ? reason.message : String(reason)}`);
    }
  };
  const netexecActions = {
    openPsexec: () => void openPsexec(), openLateral: (kind: "wmiexec" | "smbexec" | "atexec") =>
      void openLateral(kind),
    openSsh: () => void openSsh(), openWinrm: () => void openEvilWinrm(),
    copyRdp: () => void copyRdp(), openMssql: () => void openMssql(), openHashcat,
    openLookupsid, openMssqlRidBrute,
    captureEvidence: (execution: {id: number; stdout?: string; stderr?: string}, title: string) =>
      void netexecCaptureEvidence(execution, title),
    promoteFinding: (execution: {id: number; stdout?: string; stderr?: string},
      title: string, description: string) => void netexecPromoteFinding(execution, title, description),
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
      {findingFileEvidenceId !== undefined && <section style={S.executionResults} aria-label="발견된 파일 내용">
        <div style={S.executionResultsHead}>
          <strong>파일 내용</strong>
          {findingFilePreview.data?.truncated && <span style={{ color: "#e3b341" }}>일부만 표시됨</span>}
        </div>
        <div style={S.terminalBody}>
          {findingQuery.isLoading || findingFilePreview.isLoading
            ? <div style={S.resultMessage}>파일 내용 불러오는 중…</div>
            : findingFilePreview.isError
              ? <div style={S.resultError}>파일 내용을 불러오지 못했습니다.</div>
              : <pre style={S.terminalOutput}>{findingFilePreview.data?.content || "(빈 파일)"}</pre>}
        </div>
      </section>}
      {/* Zip, pcap, pdf, ... never get an inline preview -- Evidence 레일도
          screenshot 종류에만 편집 버튼을 붙여주지 다운로드 링크는 어디에도
          없었으므로, 그래프를 벗어나 별도 증적 탭을 뒤지지 않아도 원본
          파일을 받을 수 있게 여기서 바로 노출한다. */}
      {findingId !== null && !!findingQuery.data?.evidence.length && (
        <section style={S.executionResults} aria-label="연결된 Evidence">
          <div style={S.executionResultsHead}><strong>연결된 Evidence</strong></div>
          <div style={S.linkList}>
            {findingQuery.data.evidence.map((item) => {
              const isZip = /\.zip$/i.test(item.title);
              const archiveOpen = openArchiveId === item.evidence_id;
              return (
                <div key={item.id}>
                  <div style={S.linkRow}>
                    <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {item.title}
                    </span>
                    <span style={S.linkKind}>{item.kind}</span>
                    <span style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                      {isZip && <button style={S.resultAction}
                        onClick={() => {
                          setArchiveMessage("");
                          setOpenArchiveId(archiveOpen ? null : item.evidence_id);
                        }}>
                        {archiveOpen ? "압축 목록 닫기" : "압축 해제"}
                      </button>}
                      <a href={`/api/evidence/${item.evidence_id}/file`}
                        style={{ ...S.resultAction, textDecoration: "none" }}>
                        다운로드
                      </a>
                    </span>
                  </div>
                  {archiveOpen && (
                    <div style={S.netexecTree}>
                      {archiveMessage && <div style={S.resultNotice}>{archiveMessage}</div>}
                      {archiveQuery.isLoading ? (
                        <div style={S.resultMessage}>압축 목록 불러오는 중…</div>
                      ) : archiveQuery.isError ? (
                        <div style={S.resultError}>압축 목록을 불러오지 못했습니다.</div>
                      ) : !archiveQuery.data?.entries.length ? (
                        <div style={S.resultMessage}>압축 파일이 비어 있습니다.</div>
                      ) : archiveQuery.data.entries.map((entry) => {
                        const key = `${item.evidence_id}:${entry.name}`;
                        const done = extractedEntries.has(key);
                        return (
                          <div key={entry.name} style={S.linkRow}>
                            <code style={S.linkCode}>{entry.encrypted && "🔒 "}{entry.name}</code>
                            <span style={S.linkKind}>{(entry.size / 1024).toFixed(1)} KB</span>
                            <button style={S.rowAction} disabled={done || entry.encrypted}
                              title={entry.encrypted
                                ? "암호로 보호됨 -- Hash Cracking의 zip2john으로 먼저 크랙하세요" : undefined}
                              onClick={() => void extractEntry(item.evidence_id, entry.name)}>
                              {done ? "추가됨" : entry.encrypted ? "암호 필요" : "노드로 추가"}
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}
      {credentialId !== null && <section style={S.credentialDetail} aria-label="저장된 인증정보">
        <div style={S.credentialDetailHead}>
          <div style={{ display: "grid", gap: 3 }}>
            <span style={{ color: "#8f8157", fontSize: 9 }}>저장된 인증정보</span>
            <strong>{credentialQuery.data?.source_execution_kind === "hash_crack_job"
              ? "크래킹 완료 · 평문 사용 가능"
              : credentialQuery.data?.secret_kind === "hash"
                ? "크래킹 전 · 캡처된 해시" : "사용 가능한 인증정보"}</strong>
          </div>
          <b style={{ color: "#e3b341", font: "9px ui-monospace,monospace" }}>
            {(credentialQuery.data?.secret_kind || nodeMeta(n).credType || "credential").toUpperCase()}
          </b>
        </div>
        {credentialQuery.isLoading ? <div style={S.resultMessage}>인증정보 불러오는 중…</div>
          : credentialQuery.isError || !credentialQuery.data
            ? <div style={S.resultError}>저장된 인증정보를 불러오지 못했습니다.</div>
            : <>
              <dl style={S.credentialFacts}>
                <div style={{ display: "grid", gridTemplateColumns: "54px 1fr", padding: "7px 0" }}>
                  <dt style={{ color: "#756f55", fontSize: 9 }}>계정</dt>
                  <dd style={{ margin: 0, color: "#e8dfc7", fontSize: 11 }}>
                    {[credentialQuery.data.domain, credentialQuery.data.username]
                      .filter(Boolean).join("\\") || "이름 없음"}
                  </dd>
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "54px 1fr", padding: "7px 0",
                  borderTop: "1px solid #292719" }}>
                  <dt style={{ color: "#756f55", fontSize: 9 }}>출처</dt>
                  <dd style={{ margin: 0, color: "#aaa17d", fontSize: 10 }}>
                    {credentialQuery.data.source_detail || credentialQuery.data.secret_hint
                      || credentialQuery.data.source_kind || "기록 없음"}
                  </dd>
                </div>
              </dl>
              <code style={S.credentialSecret}>{credentialRevealed
                ? credentialQuery.data.secret : "••••••••••••••••••••••••"}</code>
              <div style={{ ...S.captureActions, padding: "0 12px 12px" }}>
                <button style={S.resultAction} onClick={() => setCredentialRevealed((value) => !value)}>
                  {credentialRevealed ? "숨기기"
                    : credentialQuery.data.secret_kind === "hash" ? "해시 보기" : "평문 보기"}
                </button>
                <button style={S.resultAction}
                  onClick={() => void navigator.clipboard.writeText(credentialQuery.data!.secret)}>
                  {credentialQuery.data.secret_kind === "hash" ? "해시 복사" : "평문 복사"}
                </button>
              </div>
            </>}
      </section>}
      {executionId !== null && isNetexecCheck && <section style={S.netexecNodeResult}
        aria-label="NetExec 인증 결과">
        <div style={S.netexecNodeResultHead}>
          <span>NETEXEC</span>
          <strong>{/^\[\+\]|pwn3d/im.test(executionOutput.data?.stdout || "")
            ? "인증 성공" : executionOutput.isLoading ? "결과 확인 중" : "인증 결과 확인 필요"}</strong>
        </div>
        <dl style={S.credentialFacts}>
          <div style={{ display: "grid", gridTemplateColumns: "54px 1fr", padding: "7px 0" }}>
            <dt style={{ color: "#677f71", fontSize: 9 }}>대상</dt>
            <dd style={{ margin: 0, color: "#d6e5dc", fontSize: 11 }}>
              {target?.hostname || target?.ip || "불러오는 중"}{service ? `:${service.port}` : ""}
            </dd>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "54px 1fr", padding: "7px 0",
            borderTop: "1px solid #203028" }}>
            <dt style={{ color: "#677f71", fontSize: 9 }}>실행</dt>
            <dd style={{ margin: 0, color: "#9eb5a8", fontSize: 10 }}>{command || n.label}</dd>
          </div>
        </dl>
        {netexecProtocol && executionId !== null && (
          <div style={{ padding: "0 12px 12px" }}>
            <NetexecOutcome protocol={netexecProtocol}
              result={{id: executionId, templateId: tool || "", name: n.label,
                status: executionOutput.data?.status === "completed" ? "completed" : "running",
                startedAt: 0, stdout: executionOutput.data?.stdout, stderr: executionOutput.data?.stderr}}
              username={netexecUsername} domain="" target={target} service={service}
              evidenceMsg={captureMessage} actions={netexecActions} />
          </div>
        )}
        {latestFileTree && <div style={S.netexecTree}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 8, padding: "9px 12px" }}>
            <b>폴더·파일 트리</b><span style={{ color: "#71867b", fontSize: 9 }}>
              저장된 실행 #{latestFileTree.id} · {new Date(latestFileTree.created_at).toLocaleString()}
            </span>
          </div>
          {fileTreeOutput.isLoading ? <div style={S.resultMessage}>트리 불러오는 중…</div>
            : <FileTreeView searchable onOpenFile={setOpenFilePath} runId={latestFileTree.id}
              node={buildFileTree(
              parseTaggedTreeLines(fileTreeOutput.data?.stdout || ""),
              latestFileTree.command_id.startsWith("windows_file_tree") ? "\\" : "/")} />}
        </div>}
        {latestFileTree && openFilePath !== null && <FileContentModal
          runId={latestFileTree.id} path={openFilePath} graphNodeId={n.id}
          onClose={() => setOpenFilePath(null)} />}
      </section>}
      {executionId !== null && isRedisUnauthCheck && <section style={S.netexecNodeResult}
        aria-label="Redis 무인증 접근 결과">
        <div style={S.netexecNodeResultHead}>
          <span>REDIS</span>
          <strong>{/redis_version/i.test(executionOutput.data?.stdout || "")
            ? "인증 없이 접속 가능" : executionOutput.isLoading ? "결과 확인 중" : "인증 결과 확인 필요"}</strong>
        </div>
        <dl style={S.credentialFacts}>
          <div style={{ display: "grid", gridTemplateColumns: "54px 1fr", padding: "7px 0" }}>
            <dt style={{ color: "#677f71", fontSize: 9 }}>대상</dt>
            <dd style={{ margin: 0, color: "#d6e5dc", fontSize: 11 }}>
              {target?.hostname || target?.ip || "불러오는 중"}{service ? `:${service.port}` : ""}
            </dd>
          </div>
        </dl>
        {/redis_version/i.test(executionOutput.data?.stdout || "")
          && <div style={{ padding: "0 12px 12px" }}>
            <button style={S.resultAction} onClick={() => void openRedisShell()}>
              redis-cli로 접속하기
            </button>
          </div>}
      </section>}
      {executionId !== null && isMongoCheck && mongoSuccess && (
        <UnauthAccessResult label="MONGODB" connectLabel="mongosh로 접속하기"
          onConnect={() => void openMongoShell()}
          treeLabel="데이터베이스·컬렉션 트리" tree={latestExecutionFor("mongodb-db-tree")} />
      )}
      {executionId !== null && isSnmpCheck && snmpSuccess && (
        <UnauthAccessResult label="SNMP"
          treeLabel="OID 트리 (community: public)" tree={latestExecutionFor("snmp-oid-tree")} />
      )}
      {executionId !== null && isMysqlProbeCheck && mysqlProbe && (
        <UnauthAccessResult label="MYSQL" connectLabel="mysql-client로 접속하기"
          onConnect={() => void openMysqlProbeShell()}
          treeLabel="데이터베이스·테이블 트리" tree={latestExecutionFor("mysql-db-tree")} />
      )}
      {executionId !== null && isWebdavCheck && webdavSuccess && (
        <UnauthAccessResult label="WEBDAV"
          treeLabel="WebDAV 폴더·파일 트리" tree={latestExecutionFor("http-webdav-tree")} />
      )}
      {executionId !== null && isLdapAnonCheck && ldapAnonSuccess && (
        <UnauthAccessResult label="LDAP 익명 bind"
          treeLabel="Directory Information Tree" tree={latestExecutionFor("ldap-dit-tree")} />
      )}
      {executionId !== null && isSvnCheck && svnSuccess && (
        <UnauthAccessResult label="노출된 .SVN"
          treeLabel="복구된 파일 목록" tree={latestExecutionFor("svn-dump-recover")} />
      )}
      {executionId !== null && isServiceVersionCheck && executionOutput.data?.status === "completed"
        && service && (
        <section style={S.netexecNodeResult} aria-label="제품·버전 식별 결과">
          <div style={S.netexecNodeResultHead}>
            <span>제품·버전 식별</span>
            <strong>{service.product ? "확인됨" : "식별 안 됨"}</strong>
          </div>
          <div style={{ padding: "0 12px 12px", display: "grid", gap: 4 }}>
            {service.product ? <>
              <div style={{ color: "#e7e7ee", fontSize: 12 }}>
                {[service.product, service.version].filter(Boolean).join(" ")}
                {service.extra_info && <span style={{ color: "#9a9aa6" }}> · {service.extra_info}</span>}
              </div>
              <div style={{ color: "#59f59a", fontSize: 10 }}>
                {service.name} {service.port} 서비스에 자동 반영됨 — 별도 등록 필요 없음
              </div>
            </> : (
              <div style={{ color: "#9a9aa6", fontSize: 11 }}>
                이 probe로는 제품·버전을 식별하지 못했습니다. 아래 실행 결과에서 원문을 확인하세요.
              </div>
            )}
          </div>
        </section>
      )}
      <section style={S.nodeNotes}>
        <div style={S.nodeNotesHead}>
          <span style={S.nodeNotesLabel}>작업 메모</span>
          <button style={S.nodeNotesSave} disabled={notes === (n.notes || "")}
            onClick={() => props.onSetDetails?.(n.id, { notes })}>저장</button>
        </div>
        <textarea style={S.nodeNotesArea} value={notes}
          onChange={(event) => setNotes(event.target.value)}
          placeholder="확인한 내용, 실패 원인, 다음에 볼 항목을 기록하세요." />
      </section>
      {sessionId !== null && tool === "responder-listener" && <DetachableTerminal
        id={`responder-session-${sessionId}`} label={`Responder 세션 #${sessionId}`}>
        <section className="graphSessionTerminal" aria-label="Responder 실시간 터미널">
          <header data-terminal-drag-handle>
            <span className="termDots" aria-hidden="true"><i className="termDot" />
              <i className="termDot termDot--yellow" /><i className="termDot termDot--green" /></span>
            <b>responder://session/{sessionId}</b>
            <em>{sessionQuery.data?.status || "loading"}</em>
          </header>
          <XtermOutput output={sessionLog.data || "Responder 로그를 불러오는 중입니다."}
            cursor={sessionQuery.data?.status === "running"} ariaLabel="Responder 세션 로그" />
          {n.status === "attempt-failed" && <footer>
            <button type="button" onClick={() => void retry()}>Responder 다시 시작</button>
            {retryError && <span role="alert">{retryError}</span>}
          </footer>}
        </section>
      </DetachableTerminal>}
      {retrySession && <InteractiveTerminal sessionId={retrySession.id}
        title={`Responder 재시작 · ${retrySession.command}`} autoFloat
        onClose={() => setRetrySession(null)} />}
      {manualSession && <InteractiveTerminal sessionId={manualSession.id}
        title={manualSession.title} initialInput={manualSession.initialInput} autoFloat
        onClose={() => setManualSession(null)} />}
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
      {sessionId !== null && !!ftpDownloads.data?.files.length && (
        <section style={S.executionResults} aria-label="다운로드한 파일">
          <div style={S.executionResultsHead}>
            <div><strong>다운로드한 파일</strong>{" "}
              <span>{ftpDownloads.data.files.length}개</span></div>
          </div>
          {captureMessage && <div style={S.resultNotice}>{captureMessage}</div>}
          <div style={S.captureList}>
            {ftpDownloads.data.files.map((file) => {
              const promoted = promotedDownloads.has(file.filename);
              return <article key={file.filename} style={S.captureCard}>
                <div style={S.captureHead}><b>{file.filename}</b>
                  <span>{(file.size / 1024).toFixed(1)} KB</span></div>
                <div style={S.captureActions}>
                  <button disabled={promoted} onClick={() => void promoteDownload(file.filename)}>
                    {promoted ? "그래프에 남김" : "그래프에 남기기"}
                  </button>
                </div>
              </article>;
            })}
          </div>
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
