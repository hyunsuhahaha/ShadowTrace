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
import DnsSubdomainPanel from "./DnsSubdomainPanel";
import ParamFuzzPanel from "./ParamFuzzPanel";
import LinkExtractPanel from "./LinkExtractPanel";
import S3BucketPanel from "./S3BucketPanel";
import CloudEnumPanel from "./CloudEnumPanel";
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
  isDnsLikeService,
  isHttpLikeService,
  isWinrmHttpApi,
  keepSelectedService,
  parseMysqlProbeSuccess,
  parseNfsExports,
  parseRsyncModules,
  parseSmbEnumSharesAccess,
  parseSmbShares,
  reconcileServiceNav,
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
import {consumePendingServiceNav, type PendingServiceNav} from "./pendingServiceNav";
import {focusInGraph} from "./pendingGraphFocus";

const scrollToAnchorSoon = (anchorId: string, attemptsLeft = 10) => {
  const anchor = document.getElementById(anchorId);
  if (anchor) {
    anchor.scrollIntoView({behavior: "smooth", block: "start"});
    return;
  }
  if (attemptsLeft > 0)
    window.setTimeout(() => scrollToAnchorSoon(anchorId, attemptsLeft - 1), 150);
};

export default function App({ embedded = false }: { embedded?: boolean } = {}) {
  const qc = useQueryClient();
  // Keyed by template_id: nothing backend-side serializes executions (each
  // is its own asyncio task/subprocess), so the UI tracks as many
  // concurrently-running commands as the user starts, one slot per command.
  const activeEventSourcesRef = useRef<Record<string, EventSource>>({});
  // A command-palette pick can name a target/service this page didn't
  // start on (see pendingServiceNav.ts) — set while that handoff is being
  // applied so the "default to the project's first target/service"
  // effects below don't stomp it before it lands.
  const pendingNavRef = useRef<PendingServiceNav>();
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
  const [runWithSudo, setRunWithSudoState] = useState(true);
  // run() reads runWithSudoRef (not the state var) so direct-run helpers that
  // call setRunWithSudo(false) immediately before run(...) in the same tick
  // don't leak a stale sudo choice from a previously reviewed command — state
  // updates don't flush until the next render, but the ref is synchronous.
  const runWithSudoRef = useRef(runWithSudo);
  const setRunWithSudo = (value: boolean) => {
    runWithSudoRef.current = value;
    setRunWithSudoState(value);
  };
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
  const [hostnameDraft, setHostnameDraft] = useState("");
  const [hostnameSaving, setHostnameSaving] = useState(false);
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
    if (pendingNavRef.current) return;
    setTargetId(targets.data?.[0]?.id);
  }, [projectId, targets.data]);
  useEffect(() => {
    if (targetId) dispatchEvent(new CustomEvent("oscp-target-change", {detail: targetId}));
  }, [targetId]);
  useEffect(() => {
    // Run tracking (runStates, live-stream focus) is keyed only by template
    // id, not target id, so it must be cleared explicitly on target switch —
    // otherwise a target with prior scan history shows stale/other-target
    // run status, and a switched-away-from target's in-flight completion
    // still updates the now-unfocused output/detail panes.
    Object.values(activeEventSourcesRef.current).forEach((source) => source.close());
    activeEventSourcesRef.current = {};
    focusedRunIdRef.current = undefined;
    setFocusedRunId(undefined);
    setRunStates({});
    setOutput("서비스를 선택하고 검토한 명령을 실행하세요.\n");
    setHostnameDraft("");
  }, [targetId]);
  useEffect(() => {
    const result = reconcileServiceNav(pendingNavRef.current, targetId, services.data);
    if (result.action === "apply") {
      setServiceId(result.serviceId);
      if (result.anchorId) scrollToAnchorSoon(result.anchorId);
      pendingNavRef.current = undefined;
      return;
    }
    if (result.action === "pending") return;
    setServiceId((current) => keepSelectedService(current, services.data));
  }, [targetId, services.data]);
  const applyServiceNav = (nav: PendingServiceNav) => {
    pendingNavRef.current = nav;
    setTargetId(nav.targetId);
    const result = reconcileServiceNav(nav, targetId, services.data);
    if (result.action === "apply") {
      setServiceId(result.serviceId);
      if (result.anchorId) scrollToAnchorSoon(result.anchorId);
      pendingNavRef.current = undefined;
    }
  };
  useEffect(() => {
    const nav = consumePendingServiceNav();
    if (nav) applyServiceNav(nav);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  useEffect(() => {
    const onServiceNav = () => {
      const nav = consumePendingServiceNav();
      if (nav) applyServiceNav(nav);
    };
    addEventListener("oscp-service-nav", onServiceNav);
    return () => removeEventListener("oscp-service-nav", onServiceNav);
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
  const isWinrm = !!service
    && isWinrmHttpApi(service.name, service.port, service.product);
  const isWebService = !!service && !isWinrm
    && isHttpLikeService(service.name, service.scripts);
  const isDnsService = !!service && isDnsLikeService(service.name);
  const webScheme = service?.tls || /https|ssl/i.test(service?.name || "") ? "https" : "http";
  const webPort = service && !(["http:80", "https:443"].includes(
    `${webScheme}:${service.port}`)) ? `:${service.port}` : "";
  const webUrl = target && service
    ? `${webScheme}://${target.hostname || target.ip}${webPort}/` : "";
  useEffect(() => {
    if (!target?.hostname || !target.ip) return;
    api("/hosts/sync", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({hostname: target.hostname, ip: target.ip}),
    }).catch(() => {});
  }, [target?.id, target?.hostname, target?.ip]);
  const saveHostname = async () => {
    if (!target || !hostnameDraft.trim()) return;
    setHostnameSaving(true);
    try {
      await api(`/targets/${target.id}/hostname`, {
        method: "PATCH",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({hostname: hostnameDraft.trim()}),
      });
      await qc.invalidateQueries({queryKey: ["targets", projectId]});
      setHostnameDraft("");
    } finally {
      setHostnameSaving(false);
    }
  };
  const clearHostname = async () => {
    if (!target) return;
    setHostnameSaving(true);
    try {
      await api(`/targets/${target.id}/hostname`, {
        method: "PATCH",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({hostname: ""}),
      });
      await qc.invalidateQueries({queryKey: ["targets", projectId]});
      setHostnameDraft("");
    } finally {
      setHostnameSaving(false);
    }
  };
  const selectedExecution = serviceExecutions.find(
    (item) => item.id === selectedExecutionId,
  );
  const authenticationCommands = (commands.data || []).filter((item) =>
    /(?:anon|null-session|empty-password|unauthenticated|auth-methods|default-audit|community-audit|credential-probe)/i
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
    autoRunFtpTree("", "");
  };
  const openMysqlTerminal = async (username: string) => {
    if (!targetId || !serviceId) return;
    try {
      const session = await api<any>("/interactive-sessions", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          target_id: targetId,
          service_id: serviceId,
          template_id: "mysql-client",
          variables: {username},
          run_as_root: false,
        }),
      });
      await api<any>(`/interactive-sessions/${session.id}/desktop`, {method: "POST"});
      setOutput((value) => `${value}\n[Kali QTerminal에서 MySQL 세션을 열었습니다.]\n`);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      setOutput((value) => `${value}\n[MySQL 터미널을 열지 못했습니다] ${message}\n`);
    }
  };
  const openMysqlTerminalMycli = async (username: string) => {
    if (!targetId || !serviceId) return;
    try {
      const session = await api<any>("/interactive-sessions", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          target_id: targetId,
          service_id: serviceId,
          template_id: "mysql-client-mycli",
          variables: {username},
          run_as_root: false,
        }),
      });
      await api<any>(`/interactive-sessions/${session.id}/desktop`, {method: "POST"});
      setOutput((value) => `${value}\n[Kali QTerminal에서 mycli 세션을 열었습니다.]\n`);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      setOutput((value) => `${value}\n[MySQL 터미널을 열지 못했습니다] ${message}\n`);
    }
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
            run_as_root: runWithSudoRef.current,
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
          run_as_root: runWithSudoRef.current,
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
    dispatchEvent(new CustomEvent("oscp-graph-refresh"));
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
        dispatchEvent(new CustomEvent("oscp-graph-refresh"));
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
        if (c.id === "nfs-showmount") {
          // showmount only lists the exports themselves, not what's inside
          // them -- auto-mount the first one to actually see the tree.
          // ponytail: same single-slot-executor limit as SMB's auto-spider,
          // so only the first export is fetched automatically.
          const exports = parseNfsExports(result.stdout || "");
          const key = `${targetId}-${exports[0] || ""}`;
          if (exports.length && autoNfsTreeFiredRef.current !== key) {
            autoNfsTreeFiredRef.current = key;
            autoRunNfsTree(exports[0]);
          }
        }
        if (c.id === "rsync-modules") {
          // ponytail: same single-slot-executor limit as SMB/NFS -- only
          // the first module discovered is auto-listed.
          const modules = parseRsyncModules(result.stdout || "");
          const key = `${targetId}-${modules[0] || ""}`;
          if (modules.length && autoRsyncTreeFiredRef.current !== key) {
            autoRsyncTreeFiredRef.current = key;
            autoRunRsyncTree(modules[0]);
          }
        }
        if (c.id === "docker-api-detect" && /"ApiVersion"/i.test(result.stdout || "")) {
          const key = `${targetId}-${serviceId}`;
          if (autoDockerTreeFiredRef.current !== key) {
            autoDockerTreeFiredRef.current = key;
            autoRunDockerTree();
          }
        }
        if (c.id === "mongodb-info" && /mongodb-info:/i.test(result.stdout || "")) {
          const key = `${targetId}-${serviceId}`;
          if (autoMongoTreeFiredRef.current !== key) {
            autoMongoTreeFiredRef.current = key;
            autoRunMongoTree();
          }
        }
        if (c.id === "snmp-info" && /snmp-info:/i.test(result.stdout || "")) {
          const key = `${targetId}-${serviceId}`;
          if (autoSnmpTreeFiredRef.current !== key) {
            autoSnmpTreeFiredRef.current = key;
            autoRunSnmpTree();
          }
        }
        if (c.id === "mysql-credential-probe") {
          const found = parseMysqlProbeSuccess(result.stdout || "");
          const key = `${targetId}-${found?.username || ""}-${found?.password || ""}`;
          if (found && autoMysqlTreeFiredRef.current !== key) {
            autoMysqlTreeFiredRef.current = key;
            autoRunMysqlTree(found.username, found.password);
          }
        }
        if (c.id === "redis-unauthenticated-info" && /redis_version/i.test(result.stdout || "")) {
          const key = `${targetId}-${serviceId}`;
          if (autoRedisTreeFiredRef.current !== key) {
            autoRedisTreeFiredRef.current = key;
            autoRunRedisTree();
          }
        }
        if (c.id === "http-webdav-detect" && /PROPFIND/i.test(result.stdout || "")) {
          const key = `${targetId}-${serviceId}`;
          if (autoWebdavTreeFiredRef.current !== key) {
            autoWebdavTreeFiredRef.current = key;
            autoRunWebdavTree();
          }
        }
        if (c.id === "ldap-anonymous-users" && /^\[\+\]/im.test(result.stdout || "")) {
          const key = `${targetId}-${serviceId}-anon`;
          if (autoLdapTreeFiredRef.current !== key) {
            autoLdapTreeFiredRef.current = key;
            autoRunLdapTree("", "");
          }
        }
        if (c.id === "svn-wcdb-check" && /^HTTP\/[\d.]+ 200/im.test(result.stdout || "")) {
          const key = `${targetId}-${serviceId}`;
          if (autoSvnDumpFiredRef.current !== key) {
            autoSvnDumpFiredRef.current = key;
            autoRunSvnDump();
          }
        }
        if (c.id === "git-head-check" && /ref:\s*refs\/heads\//i.test(result.stdout || "")) {
          const key = `${targetId}-${serviceId}`;
          if (autoGitDumpFiredRef.current !== key) {
            autoGitDumpFiredRef.current = key;
            autoRunGitDump();
          }
        }
        if (c.id === "git-dumper-clone") autoRunGitDumpTree();
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
  const deleteSavedExecution = async (id: number) => {
    try {
      await api(`/executions/${id}`, { method: "DELETE" });
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      setOutput((value) => `${value}\n[실행 이력 삭제 실패] ${message}\n`);
      return;
    }
    await qc.invalidateQueries({ queryKey: ["executions", targetId] });
    if (selectedExecutionId === id) {
      setSelectedExecutionId(undefined);
      setExecutionDetail(undefined);
      setExecutionView("list");
    }
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
  const autoRunFtpTree = (username: string, password: string) => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "ftp-directory-tree",
      preview: `ftp_tree --host ${target.ip} --port ${service.port}` +
        (username ? ` --username ${username} --password ***` : " (anonymous)"),
      target_level: false,
      variables: {username, password},
    });
  };
  const autoRunImapTree = (username: string, password: string) => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "imap-mailbox-tree",
      preview: `imap_tree --host ${target.ip} --port ${service.port}` +
        ` --username ${username} --password ***`,
      target_level: false,
      variables: {username, password},
    });
  };
  const autoNfsTreeFiredRef = useRef<string>();
  const autoRunNfsTree = (path: string) => {
    if (!target) return;
    setRunWithSudo(false);
    void run({
      id: "nfs-export-tree",
      preview: `nfs_tree.sh ${target.ip} ${path}`,
      target_level: true,
      variables: {path},
    });
  };
  const autoWebdavTreeFiredRef = useRef<string>();
  const autoRunWebdavTree = () => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "http-webdav-tree",
      preview: `webdav_tree --host ${target.ip} --port ${service.port} (anonymous)`,
      target_level: false,
      variables: {username: "", password: ""},
    });
  };
  const autoMysqlTreeFiredRef = useRef<string>();
  const autoRunMysqlTree = (username: string, password: string) => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "mysql-db-tree",
      preview: `mysql_db_tree --host ${target.ip} --port ${service.port}` +
        ` --username ${username} --password ***`,
      target_level: false,
      variables: {username, password},
    });
  };
  const autoRedisTreeFiredRef = useRef<string>();
  const autoRunRedisTree = () => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "redis-key-tree",
      preview: `redis_tree.sh ${target.ip} ${service.port} (no auth)`,
      target_level: false,
      variables: {password: ""},
    });
  };
  const autoRsyncTreeFiredRef = useRef<string>();
  const autoRunRsyncTree = (moduleName: string) => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "rsync-module-tree",
      preview: `rsync_tree.sh ${target.ip} ${service.port} ${moduleName}`,
      target_level: false,
      variables: {path: moduleName},
    });
  };
  const autoSnmpTreeFiredRef = useRef<string>();
  const autoRunSnmpTree = () => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "snmp-oid-tree",
      preview: `snmp_tree --host ${target.ip} --port ${service.port} --community public`,
      target_level: false,
      variables: {password: "public"},
    });
  };
  const autoMssqlTreeFiredRef = useRef<string>();
  const autoRunMssqlTree = (username: string, password: string) => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "mssql-db-tree",
      preview: `mssql_db_tree --host ${target.ip} --port ${service.port}` +
        ` --username ${username} --password ***`,
      target_level: false,
      variables: {username, password, domain: credStore.domain},
    });
  };
  const autoPostgresTreeFiredRef = useRef<string>();
  const autoRunPostgresTree = (username: string, password: string) => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "postgres-db-tree",
      preview: `postgres_db_tree --host ${target.ip} --port ${service.port}` +
        ` --username ${username} --password ***`,
      target_level: false,
      variables: {username, password},
    });
  };
  const autoDockerTreeFiredRef = useRef<string>();
  const autoRunDockerTree = () => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "docker-api-tree",
      preview: `docker_tree --host ${target.ip} --port ${service.port} (no auth)`,
      target_level: false,
      variables: {},
    });
  };
  const autoMongoTreeFiredRef = useRef<string>();
  const autoRunMongoTree = () => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "mongodb-db-tree",
      preview: `mongodb_tree --host ${target.ip} --port ${service.port} (no auth)`,
      target_level: false,
      variables: {},
    });
  };
  const autoLdapTreeFiredRef = useRef<string>();
  const autoRunLdapTree = (username: string, password: string) => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "ldap-dit-tree",
      preview: `ldap_tree --host ${target.ip} --port ${service.port}` +
        (username ? ` --username ${username} --password ***` : " (anonymous)"),
      target_level: false,
      variables: {username, password},
    });
  };
  const autoSvnDumpFiredRef = useRef<string>();
  const autoRunSvnDump = () => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "svn-dump-recover",
      preview: `svn_dump --url ${target.ip}:${service.port}`,
      target_level: false,
      variables: {},
    });
  };
  const autoGitDumpFiredRef = useRef<string>();
  const autoRunGitDump = () => {
    if (!target || !service) return;
    setRunWithSudo(false);
    void run({
      id: "git-dumper-clone",
      preview: `git-dumper ${target.ip}:${service.port}/.git/`,
      target_level: false,
      variables: {},
    });
  };
  const autoRunGitDumpTree = () => {
    setRunWithSudo(false);
    void run({
      id: "git-dump-tree", preview: "find git-dump -printf ...",
      target_level: true, variables: {},
    });
  };
  // Responder needs to keep running while the tester works in other tabs
  // (Web Testing, to trigger the auth coercion) without losing its view on
  // every SPA navigation, so unlike the manual-shell panels next to this
  // one it launches in a real Kali desktop terminal window instead of the
  // in-page xterm panel.
  const startResponderDesktop = async (interfaceName: string) => {
    if (!targetId || !interfaceName.trim()) return;
    try {
      const session = await api<any>("/interactive-sessions", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          target_id: targetId, template_id: "responder-listener",
          variables: {interface: interfaceName.trim()}, run_as_root: true,
        }),
      });
      await api<any>(`/interactive-sessions/${session.id}/desktop`, {method: "POST"});
      setOutput((value) =>
        `${value}\n$ sudo responder -I ${interfaceName.trim()} -v\n\n[Kali 데스크톱 터미널에서 실행했습니다.]\n`);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      setOutput((value) => `${value}\n[Responder 실행 실패] ${message}\n`);
    }
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
  // Same "keeps running across tab switches" reasoning as Responder — but
  // unlike openManualShell (which types a secret into an already-connected
  // PTY, never touching the backend), a desktop-launched terminal runs
  // whatever command it's given directly, so this is only safe for a
  // command with no -p/-H/password baked in. The backend rejects one
  // anyway, but the real safeguard is: never build a command with a secret
  // in it and hand it to this function.
  const openDesktopShell = async (command: string, typeAfter?: string) => {
    if (!targetId || !serviceId) return;
    try {
      const session = await api<any>("/interactive-sessions/manual", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({target_id: targetId, service_id: serviceId, command}),
      });
      // typeAfter never reaches the session row above — it's only sent to
      // this one-shot desktop-launch call, which hands it to the spawned
      // command's own password prompt through a named pipe on the backend,
      // never this command string or a process's argv.
      await api<any>(`/interactive-sessions/${session.id}/desktop`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({type_after: typeAfter ?? ""}),
      });
      setOutput((value) => `${value}\n$ ${command}\n\n[Kali 데스크톱 터미널에서 실행했습니다.]\n`);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      setOutput((value) => `${value}\n[실행 실패] ${message}\n`);
    }
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
    const base = `evil-winrm -i ${target.ip} -u ${shellQuote(credStore.username)}`;
    if (isNtlmHash(credStore.password)) {
      // evil-winrm only prompts interactively for a plaintext password —
      // hash auth has to go in as -H, so this stays on the embedded panel
      // (types into an already-connected PTY, never touches the backend).
      await openManualShell(`${base} -H ${shellQuote(credStore.password.trim())}`);
      return;
    }
    // Omitting -p makes evil-winrm prompt "Enter Password:" itself once the
    // terminal opens; the password is handed to that prompt via a named
    // pipe (see backend/app/modules/sessions/type_relay.exp) rather than
    // being baked into this command, so it never appears in argv/the DB.
    await openDesktopShell(base, credStore.password);
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
  const sendHashToCracking = (hash: string, label?: string) => {
    if (!targetId) return;
    localStorage.setItem("oscp-workspace-hash-target", String(targetId));
    localStorage.setItem("oscp-workspace-hash-value", hash);
    if (label) localStorage.setItem("oscp-workspace-hash-label", label);
    location.hash = "hash-cracking";
  };
  const saveResponderCredential = async (capture: {
    label: string; username: string; value: string; cleartext: boolean;
  }) => {
    if (!projectId || !targetId) return;
    setEvidenceMsg("");
    try {
      await api("/runbooks/credentials", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          project_id: projectId, target_id: targetId,
          username: capture.username, secret: capture.value,
          secret_kind: capture.cleartext ? "password" : "hash",
          secret_hint: capture.cleartext ? "Responder 평문 캡처" : "Responder NTLMv2-SSP 캡처",
          source_kind: "responder", source_detail: capture.label,
          service_names: [],
        }),
      });
      await qc.invalidateQueries({queryKey: ["credentials", projectId]});
      setEvidenceMsg(`${capture.username} 자격증명을 Credential Store에 저장함`);
    } catch (reason) {
      setEvidenceMsg(`저장 실패: ${reason instanceof Error ? reason.message : reason}`);
    }
  };
  const [autoFileTreeRunId, setAutoFileTreeRunId] = useState<number>();
  const [autoFileTree, setAutoFileTree] = useState<{status: string; output: string}>();
  const autoFileTreeFiredRef = useRef<string>();
  const autoFtpTreeFiredRef = useRef<string>();
  // The review-modal skip below is a deliberate exception carved out only
  // for these two read-only listing commands, hardcoded here -- there is no
  // server-side "skip review" flag (execute() already runs anything its
  // caller prepared+approved, for every command), so this function is the
  // one and only place that bypasses the modal, and it never takes a
  // command_id as input.
  const autoRunFileTree = async (
    protocol: "ssh" | "winrm", username: string, password: string, domain: string,
  ) => {
    if (!projectId || !targetId || !username.trim()) return;
    try {
      let credentialId = credStore.saved.data?.find((c) =>
        c.target_id === targetId && c.username === username && c.secret === password)?.id;
      if (!credentialId) {
        const created = await api<{id: number}>("/runbooks/credentials", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({
            project_id: projectId, target_id: targetId, username, domain,
            secret: password, secret_kind: "password", source_kind: "netexec_check",
            source_detail: `NetExec ${protocol} 자격증명 확인 성공`,
          }),
        });
        credentialId = created.id;
        await qc.invalidateQueries({queryKey: ["credentials", projectId]});
      }
      // windows_file_tree (wmiexec) goes over SMB/445 regardless of which
      // port the caller used to authenticate -- a target with only WinRM
      // reachable (verified live: 445 timed out, 5985 worked) needs the
      // WinRM-native command instead, or this silently fails every time.
      const commandId = protocol === "winrm" ? "windows_file_tree_winrm" : "linux_file_tree";
      const prepared = await api<{run: {id: number}; approval_token: string}>(
        "/post-exploitation/prepare", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({
            target_id: targetId, credential_id: credentialId, command_id: commandId,
            request_key: crypto.randomUUID(),
          }),
        });
      await api(`/post-exploitation/${prepared.run.id}/execute`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({approval_token: prepared.approval_token}),
      });
      setAutoFileTree({status: "running", output: ""});
      setAutoFileTreeRunId(prepared.run.id);
    } catch {
      // Best-effort background recon, not a user-initiated action -- a
      // failure here (no post_exploitation module installed, target
      // unreachable, etc.) shouldn't surface as an error banner.
    }
  };
  useEffect(() => {
    if (!autoFileTreeRunId) return;
    const events = new EventSource(`/api/post-exploitation/${autoFileTreeRunId}/events`);
    events.onmessage = (e) => {
      const item = JSON.parse(e.data);
      if (item.stream === "snapshot") setAutoFileTree((v) => ({...v!, output: item.data}));
      if (item.stream === "stdout")
        setAutoFileTree((v) => ({...v!, output: (v?.output || "") + item.data}));
      if (item.stream === "status") {
        setAutoFileTree((v) => ({...v!, status: item.status}));
        if (["completed", "failed", "timed_out", "cancelled"].includes(item.status))
          events.close();
      }
    };
    events.onerror = () => events.close();
    return () => events.close();
  }, [autoFileTreeRunId]);
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
  const runDirectoryFuzz = (wordlist: string, extensions: string) => {
    if (!target || !service || !wordlist.trim()) return;
    setRunWithSudo(false);
    const scheme = service.name.toLowerCase().includes("ssl") ? "https" : "http";
    const base = `feroxbuster -u ${scheme}://${target.hostname || target.ip}:${service.port}/ -w ${wordlist}`;
    void run(extensions
      ? {
          id: "http-directory-fuzz-ext",
          preview: `${base} -x ${extensions} --json --silent -n`,
          target_level: false,
          variables: {wordlist, extensions},
        }
      : {
          id: "http-directory-fuzz",
          preview: `${base} --json --silent -n`,
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
      preview: `ffuf -u ${scheme}://${target.hostname || target.ip}:${service.port}/` +
        ` -H "Host: FUZZ.${domain}" -w ${wordlist} -mc all -t 40`,
      target_level: false,
      variables: {domain, wordlist},
    });
  };
  const runDnsSubdomainEnum = (domain: string, wordlist: string) => {
    if (!target || !domain.trim() || !wordlist.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "dns-subdomain-enum",
      preview: `gobuster dns -d ${domain} -w ${wordlist} -q -i`,
      target_level: false,
      variables: {domain, wordlist},
    });
  };
  const runParamFuzz = (path: string, wordlist: string) => {
    if (!target || !service || !path.trim() || !wordlist.trim()) return;
    setRunWithSudo(false);
    const scheme = service.name.toLowerCase().includes("ssl") ? "https" : "http";
    void run({
      id: "http-param-fuzz",
      preview: `ffuf -u ${scheme}://${target.hostname || target.ip}:${service.port}${path}?FUZZ=test` +
        ` -w ${wordlist} -mc all -t 40`,
      target_level: false,
      variables: {path, wordlist},
    });
  };
  const runLinkExtract = (path: string) => {
    if (!target || !service || !path.trim()) return;
    setRunWithSudo(false);
    const scheme = service.name.toLowerCase().includes("ssl") ? "https" : "http";
    void run({
      id: "http-link-extract",
      preview: `bash -c "curl -s -k ${scheme}://${target.hostname || target.ip}:${service.port}${path}` +
        ` | grep -ohE '(href|src|action)=\\"[^\\"#]*\\"' | sed -E 's/^[a-z]+=\\"//;s/\\"$//' | sort -u"`,
      target_level: false,
      variables: {path},
    });
  };
  const openLinkInRequest = (url: string) => {
    localStorage.setItem("oscp-web-launch", JSON.stringify({
      targetId: target?.id, serviceId: service?.id, url,
    }));
    location.hash = "web";
  };
  const runS3BucketList = () => {
    if (!target || !service) return;
    setRunWithSudo(false);
    const scheme = service.name.toLowerCase().includes("ssl") ? "https" : "http";
    void run({
      id: "s3-bucket-list",
      preview: `aws --endpoint-url=${scheme}://${target.hostname || target.ip}:${service.port} s3 ls`,
      target_level: false,
      variables: {},
    });
  };
  const runS3ObjectList = (bucket: string) => {
    if (!target || !service || !bucket.trim()) return;
    setRunWithSudo(false);
    const scheme = service.name.toLowerCase().includes("ssl") ? "https" : "http";
    void run({
      id: "s3-object-list",
      preview: `aws --endpoint-url=${scheme}://${target.hostname || target.ip}:${service.port}` +
        ` s3 ls s3://${bucket}`,
      target_level: false,
      variables: {path: bucket},
    });
  };
  const runS3WebshellUpload = (bucket: string) => {
    if (!target || !service || !bucket.trim()) return;
    setRunWithSudo(false);
    const scheme = service.name.toLowerCase().includes("ssl") ? "https" : "http";
    void run({
      id: "s3-webshell-upload",
      preview: `bash backend/scripts/s3_webshell_upload.sh ` +
        `${scheme}://${target.hostname || target.ip}:${service.port} ${bucket} <output_dir>`,
      target_level: false,
      variables: {path: bucket},
    });
  };
  const runCloudEnum = (keyword: string) => {
    if (!target || !keyword.trim()) return;
    setRunWithSudo(false);
    void run({
      id: "cloud-enum-bucket-discovery",
      preview: `cloud_enum -k ${keyword}`,
      target_level: true,
      variables: {keyword},
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
  useEffect(() => {
    if (serviceNameLower !== "ftp" || !credStore.username.trim()
      || !credStore.password.trim()) return;
    const key = `${targetId}-${credStore.username}-${credStore.password}`;
    if (autoFtpTreeFiredRef.current === key) return;
    // Debounced: there's no separate "check this credential" step for FTP
    // like NetExec gives WinRM/SSH, so this doubles as the check -- firing
    // on every keystroke while the user is still typing the password would
    // spam login attempts, hence the short wait for typing to settle.
    const timer = setTimeout(() => {
      autoFtpTreeFiredRef.current = key;
      autoRunFtpTree(credStore.username, credStore.password);
    }, 600);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serviceNameLower, targetId, credStore.username, credStore.password]);
  useEffect(() => {
    if (serviceNameLower !== "postgresql" || !credStore.username.trim()
      || !credStore.password.trim()) return;
    const key = `${targetId}-${credStore.username}-${credStore.password}`;
    if (autoPostgresTreeFiredRef.current === key) return;
    // Same reasoning as FTP/IMAP: no separate credential-check step exists
    // for PostgreSQL (unlike MySQL's dedicated probe script), so this run
    // doubles as that check too, debounced so it doesn't fire mid-typing.
    const timer = setTimeout(() => {
      autoPostgresTreeFiredRef.current = key;
      autoRunPostgresTree(credStore.username, credStore.password);
    }, 600);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serviceNameLower, targetId, credStore.username, credStore.password]);
  const autoImapTreeFiredRef = useRef<string>();
  useEffect(() => {
    if (!["imap", "imaps"].includes(serviceNameLower) || !credStore.username.trim()
      || !credStore.password.trim()) return;
    const key = `${targetId}-${credStore.username}-${credStore.password}`;
    if (autoImapTreeFiredRef.current === key) return;
    // Same reasoning as FTP above: IMAP has no separate credential-check
    // step to hang an auto-trigger off of, so this run doubles as that
    // check too, debounced so it doesn't fire mid-typing.
    const timer = setTimeout(() => {
      autoImapTreeFiredRef.current = key;
      autoRunImapTree(credStore.username, credStore.password);
    }, 600);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serviceNameLower, targetId, credStore.username, credStore.password]);
  const netexecProtocol: NetexecProtocol | undefined =
    ["microsoft-ds", "netbios-ssn", "smb"].includes(serviceNameLower) ? "smb"
    : serviceNameLower === "ssh" ? "ssh"
    : isWinrm ? "winrm"
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
  useEffect(() => {
    if (netexecProtocol !== "ssh" && netexecProtocol !== "winrm") return;
    const success = netexecCredentialResult?.status === "completed"
      && /^\[\+\]|pwn3d/im.test(netexecCredentialResult.stdout || "");
    if (!success || !targetId) return;
    const key = `${targetId}-${netexecProtocol}-${credStore.username}`;
    if (autoFileTreeFiredRef.current === key) return;
    autoFileTreeFiredRef.current = key;
    void autoRunFileTree(
      netexecProtocol, credStore.username, credStore.password, credStore.domain);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [netexecProtocol, netexecCredentialResult, targetId, credStore.username]);
  useEffect(() => {
    if (netexecProtocol !== "ldap") return;
    const success = netexecCredentialResult?.status === "completed"
      && /^\[\+\]|pwn3d/im.test(netexecCredentialResult.stdout || "");
    if (!success || !targetId) return;
    const key = `${targetId}-ldap-${credStore.username}`;
    if (autoLdapTreeFiredRef.current === key) return;
    autoLdapTreeFiredRef.current = key;
    autoRunLdapTree(credStore.username, credStore.password);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [netexecProtocol, netexecCredentialResult, targetId, credStore.username]);
  useEffect(() => {
    if (netexecProtocol !== "mssql") return;
    const success = netexecCredentialResult?.status === "completed"
      && /^\[\+\]|pwn3d/im.test(netexecCredentialResult.stdout || "");
    if (!success || !targetId) return;
    const key = `${targetId}-mssql-${credStore.username}`;
    if (autoMssqlTreeFiredRef.current === key) return;
    autoMssqlTreeFiredRef.current = key;
    autoRunMssqlTree(credStore.username, credStore.password);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [netexecProtocol, netexecCredentialResult, targetId, credStore.username]);
  const latestSmbEnum = serviceExecutions
    .filter((item) => item.template_id === "smb-enum" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const smbOutput = selectedExecution?.template_id === "smb-enum"
    ? executionDetail?.stdout || ""
    : runStates["smb-enum"]?.stdout || latestSmbEnum?.stdout || "";
  const smbShares = parseSmbShares(smbOutput);
  const latestSmbEnumShares = serviceExecutions
    .filter((item) => item.template_id === "smb-enum-shares-nmap" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const smbEnumSharesOutput = selectedExecution?.template_id === "smb-enum-shares-nmap"
    ? executionDetail?.stdout || ""
    : runStates["smb-enum-shares-nmap"]?.stdout || latestSmbEnumShares?.stdout || "";
  const smbShareAccess = parseSmbEnumSharesAccess(smbEnumSharesOutput);
  return (
    <div className={embedded ? "app app--embedded" : "app"}>
      {!embedded && <EnumerationScope
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
      />}
      <main
        className="enumerationLayout"
        style={{
          "--services-width": embedded ? "0px" : `${servicesCollapsed ? 48 : servicesWidth}px`,
          "--notes-width": embedded ? "0px" : `${notesCollapsed ? 48 : notesWidth}px`,
        } as CSSProperties}
      >
        {!embedded && <aside className={`services${servicesCollapsed ? " isCollapsed" : ""}`}>
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
        </aside>}
        <section className="work" ref={workRef}>
          <div className="serviceHead">
            <div>
              <span>
                {service?.protocol || "tcp"} / {service?.port || "—"}
              </span>
              <h1>{service?.name?.toUpperCase() || "서비스 선택"}</h1>
            </div>
            <div className="serviceHeadActions">
              {isWebService&&(() => {
                const applied = target?.hostname || "";
                const hostnameCommand = targetCommands.data?.find(
                  (item: any) => item.id === "target-hostname-redirect");
                const hostnameState = ["target-hostname-redirect",
                  "target-hostname-ntlm", "target-hostname-identity"]
                  .map((id) => runStates[id]).filter((item): item is RunState => !!item)
                  .sort((a, b) => b.startedAt - a.startedAt)[0];
                const hostnameBusy = !!hostnameState
                  && ["starting", "running"].includes(hostnameState.status);
                const hostnameResult = !hostnameState || hostnameBusy ? null
                  : hostnameState.status === "completed" ? "값 미확인 · 다른 명령으로 재시도"
                  : hostnameState.status === "no_response" ? "응답 없음 · 재시도"
                  : "확인 실패 · 재시도";
                return <div className="webServiceActions webServiceActions--hostname">
                  <span>{applied
                    ? `Hostname 적용됨: ${applied}`
                    : `Hostname 미확인 · IP로 접속됩니다${hostnameResult ? ` · ${hostnameResult}` : ""}`}</span>
                  <button disabled={hostnameBusy || !hostnameCommand}
                    onClick={() => hostnameCommand && reviewCommand(hostnameCommand)}>
                    {hostnameBusy
                      ? <><span className="buttonSpinner" aria-hidden="true" />확인 중…</>
                      : applied ? "다시 확인" : "Hostname 자동 확인"}
                  </button>
                  <input placeholder={applied
                    ? "다른 값으로 변경 (예: unika.htb)"
                    : "예: unika.htb (다른 경로로 확인한 값 직접 입력)"}
                    value={hostnameDraft}
                    onChange={(event) => setHostnameDraft(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") void saveHostname();
                    }} />
                  <button disabled={hostnameSaving || !hostnameDraft.trim()}
                    onClick={() => void saveHostname()}>
                    {hostnameSaving ? "저장 중…" : applied ? "변경" : "직접 입력"}
                  </button>
                  {applied && <button disabled={hostnameSaving}
                    onClick={() => void clearHostname()}>
                    {hostnameSaving ? "저장 중…" : "제거"}
                  </button>}
                </div>;
              })()}
              {isWebService&&webUrl&&<div className="webServiceActions">
                <a href={webUrl} target="_blank" rel="noreferrer">사이트 열기 ↗</a>
                <button onClick={()=>{
                  localStorage.setItem("oscp-web-launch",JSON.stringify({
                    targetId:target?.id,serviceId:service?.id,url:webUrl,
                  }));
                  location.hash="web";
                }}>Web Testing에서 열기</button>
              </div>}
              {isWinrm&&<div className="webServiceActions webServiceActions--hostname">
                <span>WinRM(HTTP.sys) 리스너 · 브라우저로 열람 불가 · 아래 NetExec 자격증명 확인으로 진행하세요</span>
              </div>}
              {service&&<div className="webServiceActions">
                <button onClick={()=>focusInGraph({kind:"service",id:service.id})}>
                  그래프에서 보기 ↗
                </button>
              </div>}
              <div className="risk">수동 확인 필요</div>
            </div>
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
            executions={serviceExecutions}
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
            key={`credential-audit-${serviceId}`}
            ref={credentialAuditRef}
            profile={credentialProfile}
            serviceName={service?.name}
            commands={authenticationCommands}
            runStates={runStates}
            clock={clock}
            onReview={reviewCommand}
            onOpenTerminal={service?.name?.toLowerCase() === "mysql" ? openMysqlTerminal : undefined}
            onOpenTerminalMycli={service?.name?.toLowerCase() === "mysql" ? openMysqlTerminalMycli : undefined}
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
          {!!service && <ResponderPanel targetId={targetId} evidenceMsg={evidenceMsg}
            onStartListener={(interfaceName) => void startResponderDesktop(interfaceName)}
            onSendHashToCracking={(capture) => sendHashToCracking(capture.value,
              `Responder · ${capture.username} · ${target?.ip || ""}`)}
            onSaveCredential={(capture) => void saveResponderCredential(capture)} />}
          {!!service && <DpapiDecoderPanel />}
          {!!service && <PuttyKeyConverter />}
          {!!service && <PypykatzLsassPanel />}
          {!!service && <RecycleBinDecoder />}
          <JobStatus run={focusedRun} clock={clock} activeCount={activeRuns.length} />
          <SmbShareResults key={`smb-share-${serviceId}`} targetId={targetId} serviceId={serviceId}
            shares={smbShares} shareAccess={smbShareAccess} activeShare={lastSpiderShare}
            runState={runStates["smb-share-spider"]}
            serviceExecutions={serviceExecutions} onSpider={spiderSmbShare}
            onViewFile={viewSmbFile}
            onLog={(line) => setOutput((value) => `${value}\n${line}\n`)} />
          {isDnsService && (
            <DnsSubdomainPanel target={target}
              runState={runStates["dns-subdomain-enum"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onFuzz={runDnsSubdomainEnum}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {isWebService && (
            <FuzzingPanel target={target} service={service}
              runState={runStates["http-directory-fuzz"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onFuzz={runDirectoryFuzz}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {isWebService && (
            <VhostFuzzPanel target={target}
              runState={runStates["http-vhost-fuzz"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onFuzz={runVhostFuzz}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {isWebService && (
            <ParamFuzzPanel target={target}
              runState={runStates["http-param-fuzz"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onFuzz={runParamFuzz}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {isWebService && (
            <LinkExtractPanel target={target} service={service}
              runState={runStates["http-link-extract"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onFuzz={runLinkExtract} onOpenInRequest={openLinkInRequest}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {isWebService && (
            <S3BucketPanel target={target}
              bucketRunState={runStates["s3-bucket-list"]}
              objectRunState={runStates["s3-object-list"]}
              uploadRunState={runStates["s3-webshell-upload"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onListBuckets={runS3BucketList}
              onListObjects={runS3ObjectList}
              onUploadWebshell={runS3WebshellUpload}
              onCaptureEvidence={(execution, title) => void captureEvidence(execution, title)} />
          )}
          {isWebService && (
            <CloudEnumPanel target={target}
              runState={runStates["cloud-enum-bucket-discovery"]}
              serviceExecutions={serviceExecutions} evidenceMsg={evidenceMsg}
              onEnum={runCloudEnum}
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
          {isWebService && (
            <RoundcubeDesDecoder />
          )}
          {isWebService && (
            <GiteaHashFormatter />
          )}
          {!!netexecProtocol && (
            <section className="netexecCredCheck"
              aria-labelledby="netexec-cred-heading">
              <header>
                <h2 id="netexec-cred-heading">
                  {netexecProtocol.toUpperCase()} 자격증명 확인 (NetExec)
                </h2>
              </header>
              <CredentialStoreForm store={credStore}
                result={netexecCredentialResult} onCheck={checkNetexecCredential} />
              <NetexecOutcome protocol={netexecProtocol}
                result={netexecCredentialResult} username={credStore.username}
                domain={credStore.domain} target={target} service={service}
                evidenceMsg={evidenceMsg} fileTree={autoFileTree} actions={{
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
            onClose={() => setPsexecSession(undefined)}
            onSendHashToCracking={(hash) => sendHashToCracking(hash, "PTY 세션 로그 캡처")}
            targetId={targetId} />
          <LiveOutputPanel run={focusedRun} elapsed={runElapsed}
            outcome={currentOutcome} output={output} />
        </section>
        {!embedded && <aside ref={notesRef} className={`notes${notesCollapsed ? " isCollapsed" : ""}`}
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
            onDelete={deleteSavedExecution}
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
        </aside>}
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
