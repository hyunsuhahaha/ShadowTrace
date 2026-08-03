import {
  useEffect, useRef, useState,
  type CSSProperties, type PointerEvent as ReactPointerEvent,
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import ServiceIntelligencePanel from "./ServiceIntelligencePanel";
import "./service-intelligence.css";
import { statusCopy as statusLabel } from "./ui";
import { getServiceGuidance } from "./serviceGuidance";
import { getCredentialAuditProfile } from "./credentialAudit";
import { summarizeCredentialAudit } from "./credentialAuditResult";
import { useCredentialStore } from "./useCredentialStore";
import FuzzingPanel from "./FuzzingPanel";
import VhostFuzzPanel from "./VhostFuzzPanel";
import KerbruteEnumPanel from "./KerbruteEnumPanel";
import AsrepRoastPanel from "./AsrepRoastPanel";
import PasswordSprayPanel from "./PasswordSprayPanel";
import DomainDominancePanel from "./DomainDominancePanel";
import SilverTicketPanel from "./SilverTicketPanel";
import ConstrainedDelegationPanel from "./ConstrainedDelegationPanel";
import CiscoType7Decoder from "./CiscoType7Decoder";
import GppCpasswordDecoder from "./GppCpasswordDecoder";
import VncPasswordDecoder from "./VncPasswordDecoder";
import RoundcubeDesDecoder from "./RoundcubeDesDecoder";
import DpapiDecoderPanel from "./DpapiDecoderPanel";
import PuttyKeyConverter from "./PuttyKeyConverter";
import PypykatzLsassPanel from "./PypykatzLsassPanel";
import RecycleBinDecoder from "./RecycleBinDecoder";
import GiteaHashFormatter from "./GiteaHashFormatter";
import ReverseShellPanel from "./ReverseShellPanel";
import ChiselPivotPanel from "./ChiselPivotPanel";
import ResponderPanel from "./ResponderPanel";
import SmbShareResults from "./SmbShareResults";
import ServiceList from "./ServiceList";
import ExecutionHistory from "./ExecutionHistory";
import ExecutionMonitor from "./ExecutionMonitor";
import ServiceWorkspace from "./ServiceWorkspace";
import CommandReviewModal from "./CommandReviewModal";
import EnumerationScope from "./EnumerationScope";
import CredentialAuditPanel from "./CredentialAuditPanel";
import ServiceDashboard from "./ServiceDashboard";
import InvestigationCommandList from "./InvestigationCommandList";
import ManualGuidance from "./ManualGuidance";
import JobStatus from "./JobStatus";
import CredentialStoreForm from "./CredentialStoreForm";
import NetexecOutcome, {type NetexecProtocol} from "./NetexecOutcome";
import PrivescSessionPanel from "./PrivescSessionPanel";
import LiveOutputPanel from "./LiveOutputPanel";
import {
  keepSelectedService,
  parseSmbShares,
  summarizeExecutionResult,
} from "./serviceIntel";
import {
  impacketAuthArgs,
  isNtlmHash,
  shellQuote,
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
  const [saveHashMsg, setSaveHashMsg] = useState("");
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
  const [outputFilename, setOutputFilename] = useState("");
  // Most recently derived (extracted-column) file path, offered as a
  // one-click wordlist fill for AS-REP roasting / Kerbrute panels.
  const [derivedWordlistPath, setDerivedWordlistPath] = useState("");
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
  const authenticationCommands = (commands.data || []).filter((item) =>
    /(?:anon|null-session|empty-password|unauthenticated|auth-methods|default-audit|community-audit)/i
      .test(item.id),
  );
  const credentialProfile = getCredentialAuditProfile(service?.name);
  const reviewCommand = (command: any) => {
    setRunWithSudo(Boolean(command.sudo));
    setOutputFilename("");
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
    // Consume-and-clear so a filename typed for one review doesn't leak into
    // the next direct-run call (Kerbrute, AS-REP…) which skips the modal.
    const requestedFilename = outputFilename.trim();
    setOutputFilename("");
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
          output_filename: requestedFilename,
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
    const auth = impacketAuthArgs(
      credStore.domain, credStore.username, credStore.password, target.ip);
    await openManualShell(`impacket-psexec ${auth}`);
  };
  const openLateralShell = async (tool: "wmiexec" | "smbexec" | "atexec") => {
    if (!target) return;
    const auth = impacketAuthArgs(
      credStore.domain, credStore.username, credStore.password, target.ip);
    await openManualShell(`impacket-${tool} ${auth}`);
  };
  const openListenerShell = async (port: string) => {
    if (!targetId || !serviceId || !port.trim()) return;
    await openManualShell(`nc -lvnp ${port.trim()}`);
  };
  const openSshShell = async () => {
    if (!target || !service || !credStore.username.trim()) return;
    await openManualShell(
      `ssh ${shellQuote(`${credStore.username}@${target.ip}`)} -p ${service.port}`,
    );
  };
  const openEvilWinrmShell = async () => {
    if (!target || !credStore.username.trim()) return;
    const secretFlag = isNtlmHash(credStore.password)
      ? `-H ${shellQuote(credStore.password.trim())}`
      : `-p ${shellQuote(credStore.password)}`;
    await openManualShell(
      `evil-winrm -i ${target.ip} -u ${shellQuote(credStore.username)} ${secretFlag}`,
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
    const auth = impacketAuthArgs(
      credStore.domain, credStore.username, credStore.password, target.ip);
    await openManualShell(
      `impacket-mssqlclient ${auth} -port ${service.port}`,
    );
  };
  const openHashcatShell = (mode: string = "kerberoast") => {
    if (!targetId) return;
    localStorage.setItem("oscp-workspace-hash-target", String(targetId));
    localStorage.setItem("oscp-workspace-hash-mode", mode);
    location.hash = "hash-cracking";
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
  const runVhostFuzz = (domain: string, wordlist: string) => {
    if (!target || !service || !domain.trim() || !wordlist.trim()) return;
    setRunWithSudo(false);
    const scheme = service.name.toLowerCase().includes("ssl") ? "https" : "http";
    void run({
      id: "http-vhost-fuzz",
      preview: `ffuf -u ${scheme}://${target.ip}:${service.port}/` +
        ` -H "Host: FUZZ.${domain}" -w ${wordlist} -mc all -t 40`,
      target_level: false,
      variables: {domain, wordlist},
    });
  };
  const runKerbruteEnum = (domain: string, wordlist: string) => {
    if (!target || !service || !domain.trim() || !wordlist.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "kerberos-user-enum-kerbrute",
      preview: `kerbrute userenum -d ${domain} --dc ${target.ip} ${wordlist}`,
      target_level: false,
      variables: {domain, wordlist},
    });
  };
  const runAsrepRoast = (domain: string, wordlist: string) => {
    if (!target || !domain.trim() || !wordlist.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "ad-asreproast-impacket",
      preview: `impacket-GetNPUsers ${domain}/ -usersfile ${wordlist} -no-pass` +
        ` -dc-ip ${target.ip} -outputfile <output_dir>/asrep-hashes.txt`,
      target_level: true,
      variables: {domain, wordlist},
    });
  };
  const runPasswordSpray = (wordlist: string, password: string) => {
    if (!target || !wordlist.trim() || !password.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "ad-password-spray-netexec",
      preview: `nxc ldap ${target.ip} -u ${wordlist} -p ${password} --continue-on-success`,
      target_level: true,
      variables: {wordlist, password},
    });
  };
  const runBloodhoundCollect = () => {
    if (!target || !credStore.username.trim() || !credStore.password.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "ad-bloodhound-collect",
      preview: `bloodhound-python -u ${credStore.username} -p *** -d ${credStore.domain}` +
        ` -ns ${target.ip} -c All --zip`,
      target_level: true,
      variables: {
        username: credStore.username, password: credStore.password,
        domain: credStore.domain,
      },
    });
  };
  const runGmsa = () => {
    if (!target || !credStore.username.trim() || !credStore.password.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "ad-gmsa-password-netexec",
      preview: `nxc ldap ${target.ip} -u ${credStore.username} -p *** --gmsa`,
      target_level: true,
      variables: {username: credStore.username, password: credStore.password},
    });
  };
  const runLaps = () => {
    if (!target || !credStore.username.trim() || !credStore.password.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "ad-laps-password-netexec",
      preview: `nxc ldap ${target.ip} -u ${credStore.username} -p *** --laps`,
      target_level: true,
      variables: {username: credStore.username, password: credStore.password},
    });
  };
  const runDcsync = () => {
    if (!target || !credStore.username.trim() || !credStore.password.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "ad-dcsync-secretsdump",
      preview: `impacket-secretsdump ${credStore.domain}/${credStore.username}:***` +
        `@${target.ip} -just-dc`,
      target_level: true,
      variables: {
        username: credStore.username, password: credStore.password,
        domain: credStore.domain,
      },
    });
  };
  const runSilverTicketForge = (fields: {
    nthash: string; domain: string; domainSid: string;
    spn: string; groups: string; targetUsername: string;
  }) => {
    if (!target) return;
    setRunWithSudo(false);
    void run({
      id: "ad-silver-ticket-ticketer",
      preview: `impacket-ticketer -nthash *** -domain-sid ${fields.domainSid}` +
        ` -domain ${fields.domain} -spn ${fields.spn} -groups ${fields.groups}` +
        ` ${fields.targetUsername}`,
      target_level: true,
      variables: {
        nthash: fields.nthash, domain_sid: fields.domainSid, domain: fields.domain,
        spn: fields.spn, groups: fields.groups, target_username: fields.targetUsername,
      },
    });
  };
  const runConstrainedDelegation = (fields: {
    spn: string; targetUsername: string; domain: string; username: string; password: string;
  }) => {
    if (!target) return;
    setRunWithSudo(false);
    void run({
      id: "ad-constrained-delegation-getst",
      preview: `impacket-getST -spn ${fields.spn} -impersonate ${fields.targetUsername}` +
        ` -dc-ip ${target.ip} ${fields.domain}/${fields.username}:***`,
      target_level: true,
      variables: {
        spn: fields.spn, target_username: fields.targetUsername, domain: fields.domain,
        username: fields.username, password: fields.password,
      },
    });
  };
  const saveDcsyncHash = async (dumpedUsername: string, nthash: string) => {
    if (!projectId || !targetId) return;
    setSaveHashMsg("");
    try {
      await api("/runbooks/credentials", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          project_id: projectId, target_id: targetId,
          username: dumpedUsername, domain: credStore.domain,
          secret: nthash, secret_hint: "NTLM hash (DCSync)",
          source_kind: "dcsync", source_detail: `DCSync via ${credStore.username}`,
          service_names: [],
        }),
      });
      await qc.invalidateQueries({queryKey: ["credentials", projectId]});
      setSaveHashMsg(`${dumpedUsername} 해시를 Credential Store에 저장함`);
    } catch (reason) {
      setSaveHashMsg(`저장 실패: ${reason instanceof Error ? reason.message : reason}`);
    }
  };
  const runLookupsid = () => {
    if (!target || !credStore.username.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "ad-lookupsid-impacket",
      preview: `impacket-lookupsid ${credStore.domain || "WORKGROUP"}/` +
        `${credStore.username}:***@${target.ip}`,
      target_level: true,
      variables: {
        username: credStore.username, password: credStore.password,
        domain: credStore.domain || "WORKGROUP",
      },
    });
  };
  const runMssqlRidBrute = () => {
    if (!target || !service || !credStore.username.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "mssql-rid-brute-netexec",
      preview: `nxc mssql ${target.ip} --port ${service.port}` +
        ` -u ${credStore.username} -p *** --rid-brute`,
      target_level: false,
      variables: {username: credStore.username, password: credStore.password},
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
  const netexecProtocol: NetexecProtocol | undefined =
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
  const latestSmbEnum = serviceExecutions
    .filter((item) => item.template_id === "smb-enum" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const smbOutput = selectedExecution?.template_id === "smb-enum"
    ? executionDetail?.stdout || ""
    : runStates["smb-enum"]?.stdout || latestSmbEnum?.stdout || "";
  const smbShares = parseSmbShares(smbOutput);
  return (
    <div className="app">
      <EnumerationScope
        project={project}
        target={target}
        projects={projects.data}
        targets={targets.data}
        projectId={projectId}
        targetId={targetId}
        toolsLoading={status.isLoading}
        missingTools={missingTools}
        onCreateProject={() => createProject.mutate()}
        onSelectProject={(id) => {
          setProjectId(id);
          localStorage.setItem("oscp-workspace-project", String(id));
          dispatchEvent(new CustomEvent("oscp-project-change", {detail: id}));
        }}
        onCreateTarget={() => createTarget.mutate()}
        onSelectTarget={setTargetId}
        onUpload={upload}
      />
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
          <ServiceDashboard
            service={service}
            target={target}
            commands={commands.data}
            targetCommands={targetCommands.data}
            executions={serviceExecutions}
            runStates={runStates}
            clock={clock}
            onReview={reviewCommand}
          />
          <CredentialAuditPanel
            ref={credentialAuditRef}
            profile={credentialProfile}
            serviceName={service?.name}
            commands={authenticationCommands}
            runStates={runStates}
            clock={clock}
            onReview={reviewCommand}
          />
          <InvestigationCommandList
            commands={commands.data || []}
            executions={executions.data || []}
            target={target}
            service={service}
            runStates={runStates}
            clock={clock}
            onReview={reviewCommand}
          />
          <ManualGuidance serviceName={service?.name} guidance={guidance} />
          {!!service && <ReverseShellPanel
            onStartListener={(port) => void openListenerShell(port)} />}
          {!!service && <ChiselPivotPanel
            onStartListener={(command) => void openManualShell(command)} />}
          {!!service && <ResponderPanel
            onStartListener={(command) => void openManualShell(command)} />}
          {!!service && <DpapiDecoderPanel />}
          {!!service && <PuttyKeyConverter />}
          {!!service && <PypykatzLsassPanel />}
          {!!service && <RecycleBinDecoder />}
          <JobStatus run={focusedRun} clock={clock} activeCount={activeRuns.length} />
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
          {["http", "https", "http-proxy", "ssl/http"].includes(serviceNameLower) && (
            <VhostFuzzPanel target={target}
              runState={runStates["http-vhost-fuzz"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onFuzz={runVhostFuzz}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {["kerberos-sec", "kerberos"].includes(serviceNameLower) && (
            <KerbruteEnumPanel target={target} service={service}
              runState={runStates["kerberos-user-enum-kerbrute"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              wordlistSuggestion={derivedWordlistPath}
              onEnum={runKerbruteEnum}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {["kerberos-sec", "kerberos"].includes(serviceNameLower) && (
            <AsrepRoastPanel target={target}
              runState={runStates["ad-asreproast-impacket"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              wordlistSuggestion={derivedWordlistPath}
              onRoast={runAsrepRoast}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)}
              onOpenHashcat={() => openHashcatShell("asreproast")} />
          )}
          {["ldap", "ldaps"].includes(serviceNameLower) && (
            <PasswordSprayPanel target={target}
              runState={runStates["ad-password-spray-netexec"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              wordlistSuggestion={derivedWordlistPath}
              onSpray={runPasswordSpray}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {["ldap", "ldaps"].includes(serviceNameLower) && (
            <DomainDominancePanel target={target}
              domain={credStore.domain} username={credStore.username}
              password={credStore.password}
              bloodhoundRunState={runStates["ad-bloodhound-collect"]}
              dcsyncRunState={runStates["ad-dcsync-secretsdump"]}
              gmsaRunState={runStates["ad-gmsa-password-netexec"]}
              lapsRunState={runStates["ad-laps-password-netexec"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onCollectBloodhound={runBloodhoundCollect} onDcsync={runDcsync}
              onGmsa={runGmsa} onLaps={runLaps}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)}
              onFillCredential={(u, h) => { credStore.setUsername(u); credStore.setPassword(h); }}
              onSaveHash={(u, h) => void saveDcsyncHash(u, h)}
              saveHashMsg={saveHashMsg} />
          )}
          {["ldap", "ldaps"].includes(serviceNameLower) && (
            <SilverTicketPanel target={target}
              runState={runStates["ad-silver-ticket-ticketer"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              dcsyncStdout={runStates["ad-dcsync-secretsdump"]?.stdout}
              onForge={runSilverTicketForge}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {["ldap", "ldaps"].includes(serviceNameLower) && (
            <ConstrainedDelegationPanel target={target}
              runState={runStates["ad-constrained-delegation-getst"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onRequest={runConstrainedDelegation}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {["microsoft-ds", "netbios-ssn", "smb"].includes(serviceNameLower) && (
            <CiscoType7Decoder />
          )}
          {["microsoft-ds", "netbios-ssn", "smb"].includes(serviceNameLower) && (
            <GppCpasswordDecoder />
          )}
          {["microsoft-ds", "netbios-ssn", "smb"].includes(serviceNameLower) && (
            <VncPasswordDecoder />
          )}
          {["http", "https", "http-proxy", "ssl/http"].includes(serviceNameLower) && (
            <RoundcubeDesDecoder />
          )}
          {["http", "https", "http-proxy", "ssl/http"].includes(serviceNameLower) && (
            <GiteaHashFormatter />
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
              <CredentialStoreForm store={credStore}
                result={netexecCredentialResult} onCheck={checkNetexecCredential} />
              <NetexecOutcome protocol={netexecProtocol}
                result={netexecCredentialResult} username={credStore.username}
                domain={credStore.domain} target={target} service={service}
                evidenceMsg={evidenceMsg} actions={{
                  openPsexec: () => void openPsexecShell(),
                  openLateral: (kind) => void openLateralShell(kind),
                  openSsh: () => void openSshShell(),
                  openWinrm: () => void openEvilWinrmShell(),
                  copyRdp: () => void copyXfreerdpCommand(),
                  openMssql: () => void openMssqlShell(),
                  openHashcat: () => void openHashcatShell(),
                  openLookupsid: () => void runLookupsid(),
                  openMssqlRidBrute: () => void runMssqlRidBrute(),
                  captureEvidence: (execution, title) => void captureEvidence(
                    execution, title, "sensitive"),
                  promoteFinding: (execution, title, description) => void promoteToFinding(
                    execution, title, description, "sensitive"),
                }} />
            </section>
          )}
          <PrivescSessionPanel session={psexecSession} server={privescServer}
            serverBusy={privescServerBusy} inputRequest={psexecInputRequest}
            onToggleServer={() => void togglePrivescServer()}
            onSendCommand={(command) => void sendPrivescCommand(command)}
            onClose={() => setPsexecSession(undefined)} />
          <LiveOutputPanel run={focusedRun} elapsed={runElapsed}
            outcome={currentOutcome} output={output} />
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
            onDerived={setDerivedWordlistPath}
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
          <ServiceWorkspace target={target}
            draft={{product: serviceProduct, version: serviceVersion,
              tags: serviceTags, notes: serviceNotes}}
            saveState={serviceSaveState} disabled={!serviceId}
            collapsed={workspaceCollapsed}
            onDraft={(draft) => {
              setServiceProduct(draft.product);
              setServiceVersion(draft.version);
              setServiceTags(draft.tags);
              setServiceNotes(draft.notes);
            }}
            onSave={saveService}
            onToggle={() => setWorkspaceCollapsed((collapsed) => {
              localStorage.setItem("oscp-service-workspace-collapsed", String(!collapsed));
              return !collapsed;
            })} />
        </aside>
      </main>
      <ExecutionMonitor runs={activeRuns} focusedId={focusedRunId} now={clock}
        onFocus={(templateId) => {
          focusedRunIdRef.current = templateId;
          setFocusedRunId(templateId);
        }}
        onStop={(templateId) => void stopRun(templateId)} />
      <CommandReviewModal command={confirm} runWithSudo={runWithSudo}
        onSudo={setRunWithSudo} outputFilename={outputFilename}
        onOutputFilename={setOutputFilename} onCancel={() => setConfirm(null)}
        onRun={() => void run()} />
    </div>
  );
}
