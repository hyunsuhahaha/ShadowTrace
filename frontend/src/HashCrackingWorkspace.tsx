import {
  useEffect, useRef, useState,
  type CSSProperties, type PointerEvent as ReactPointerEvent,
} from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { syncSelectedProject } from "./scanCenterModel";
import { Badge, ErrorState, LoadingState, statusCopy as statusLabel } from "./ui";
import {DetachableTerminal} from "./FloatingTerminal";
import "./hash-cracking.css";

type Project = { id: number; name: string };
type Target = {
  id: number; project_id: number; name: string; ip: string;
};
type HashMode = { id: string; name: string; mode: string; example: string; detect: string };
type Wordlist = { id: string; name: string; path: string; installed: boolean; hint?: string };
type Rule = { id: string; name: string; path: string; installed: boolean };
type Catalog = {
  hash_modes: HashMode[]; wordlists: Wordlist[]; rules: Rule[]; hashcat_installed: boolean;
};
type Job = {
  id: number; project_id: number; target_id: number; label: string;
  hash_mode_id: string; hash_mode: string; hash_type_name: string;
  attack_mode: string; wordlist_id: string; wordlist2_id: string; rule_id: string;
  mask: string; hash_count: number;
  command_display: string; status: string; exit_code: number | null;
  cracked_count: number; cancelled: boolean; error: string;
  started_at?: string; ended_at?: string; evidence_id: number | null; created_at: string;
};
type Cracked = { hash: string; plain: string };

const terminal = ["completed", "failed", "cancelled"];

// hashcat -a: which attack modes need a wordlist and/or a mask, so the form
// can show only the fields that apply.
const ATTACK_MODES: {
  id: string; name: string; needsWordlist: boolean; needsWordlist2: boolean;
  needsMask: boolean; needsRule: boolean;
}[] = [
  {id: "0", name: "0 · 사전 대입 (Straight)", needsWordlist: true,
    needsWordlist2: false, needsMask: false, needsRule: true},
  {id: "1", name: "1 · 조합 (Combination)", needsWordlist: true,
    needsWordlist2: true, needsMask: false, needsRule: false},
  {id: "3", name: "3 · 브루트포스 (Mask)", needsWordlist: false,
    needsWordlist2: false, needsMask: true, needsRule: false},
  {id: "6", name: "6 · 하이브리드: 워드리스트 + 마스크", needsWordlist: true,
    needsWordlist2: false, needsMask: true, needsRule: false},
  {id: "7", name: "7 · 하이브리드: 마스크 + 워드리스트", needsWordlist: true,
    needsWordlist2: false, needsMask: true, needsRule: false},
];

// Checked in catalog order against the first non-empty pasted line so the
// mode dropdown can pre-select itself; returns undefined rather than
// guessing when nothing recognizable matches.
export function detectHashMode(hashes: string, modes: HashMode[]): string | undefined {
  const sample = hashes.split(/\r?\n/).find((line) => line.trim())?.trim();
  if (!sample) return undefined;
  return modes.find((mode) => {
    try {
      return new RegExp(mode.detect).test(sample);
    } catch {
      return false;
    }
  })?.id;
}

const get = async <T,>(path: string): Promise<T> => {
  const r = await fetch("/api" + path);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};
const post = async <T,>(path: string, body: unknown): Promise<T> => {
  const r = await fetch("/api" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};

export default function HashCrackingWorkspace({ embedded = false, initialProjectId,
  initialTargetId, initialHash = "", initialMode, initialCredentialId, initialUsername, onBack }: {
  embedded?: boolean; initialProjectId?: number; initialTargetId?: number;
  initialHash?: string; initialMode?: string; initialCredentialId?: number;
  initialUsername?: string; onBack?: () => void;
} = {}) {
  const qc = useQueryClient();
  const [projectId, setProjectId] = useState<number | undefined>(initialProjectId);
  const [targetId, setTargetId] = useState<number | undefined>(initialTargetId);
  const [label, setLabel] = useState("");
  const [hashModeId, setHashModeId] = useState<string | undefined>(initialMode);
  const [hashModeAuto, setHashModeAuto] = useState(false);
  const [hashes, setHashes] = useState(initialHash);
  const [attackMode, setAttackMode] = useState("0");
  const [wordlistId, setWordlistId] = useState<string>();
  const [wordlist2Id, setWordlist2Id] = useState<string>();
  const [ruleId, setRuleId] = useState<string>("");
  const [mask, setMask] = useState("");
  const [jobId, setJobId] = useState<number>();
  const [zipUploading, setZipUploading] = useState(false);
  const [zipError, setZipError] = useState("");
  const [zipFileName, setZipFileName] = useState("");
  const [error, setError] = useState("");
  const [output, setOutput] = useState("작업을 만들고 실행하면 실시간 출력이 표시됩니다.\n");
  const [promoteFor, setPromoteFor] = useState<Cracked>();
  const [promoteUsername, setPromoteUsername] = useState("");
  const [promoteMsg, setPromoteMsg] = useState("");
  const [copiedPlain, setCopiedPlain] = useState<string>();
  // history is polled every 3s, so relying on it alone left the status
  // badge showing "작업 대기" for up to 3s after a job actually started (the
  // live output was already streaming in via SSE the whole time) — this is
  // the immediately-known status, reconciled with history once it catches up.
  const [liveStatus, setLiveStatus] = useState<string>();
  const [formWidth, setFormWidth] = useState(() => {
    const saved = Number(localStorage.getItem("oscp-crack-form-width"));
    return saved >= 240 && saved <= 480 ? saved : 300;
  });
  const [historyWidth, setHistoryWidth] = useState(() => {
    const saved = Number(localStorage.getItem("oscp-crack-history-width"));
    return saved >= 200 && saved <= 420 ? saved : 260;
  });
  const formResize = useRef({x: 0, width: 300});
  const historyResize = useRef({x: 0, width: 260});

  const projects = useQuery({
      queryKey: ["projects"],
      queryFn: () => get<Project[]>("/projects"),
    }),
    targets = useQuery({
      queryKey: ["allTargets"],
      queryFn: () => get<Target[]>("/targets"),
    }),
    catalog = useQuery({
      queryKey: ["hashCrackingCatalog"],
      queryFn: () => get<Catalog>("/hash-cracking/catalog"),
    }),
    history = useQuery({
      queryKey: ["hashCrackingJobs", targetId],
      queryFn: () => get<Job[]>(`/hash-cracking?target_id=${targetId}`),
      enabled: !!targetId,
      refetchInterval: 3000,
    }),
    outputQuery = useQuery({
      queryKey: ["hashCrackingOutput", jobId],
      queryFn: () => get<{ stdout: string; stderr: string; cracked: Cracked[] }>(
        `/hash-cracking/${jobId}/output`),
      enabled: !!jobId,
    });

  useEffect(() => {
    if (!projectId && projects.data?.length) {
      const saved = Number(localStorage.getItem("oscp-workspace-project"));
      setProjectId(projects.data.some((p) => p.id === saved) ? saved : projects.data[0].id);
    }
  }, [projectId, projects.data]);
  useEffect(() => {
    const candidates = targets.data?.filter((item) => item.project_id === projectId);
    if (candidates?.length && !candidates.some((item) => item.id === targetId)) {
      setTargetId(candidates[0].id);
    }
  }, [projectId, targets.data, targetId]);
  useEffect(() => {
    if (targetId) dispatchEvent(new CustomEvent("oscp-target-change", { detail: targetId }));
  }, [targetId]);
  useEffect(() => {
    const requestedTarget = Number(localStorage.getItem("oscp-workspace-hash-target"));
    const match = targets.data?.find((item) => item.id === requestedTarget);
    if (match) {
      setProjectId(match.project_id);
      setTargetId(match.id);
      localStorage.removeItem("oscp-workspace-hash-target");
    }
  }, [targets.data]);
  const target = targets.data?.find((item) => item.id === targetId);
  useEffect(() => {
    if (target) syncSelectedProject(target.project_id);
  }, [target]);
  useEffect(() => {
    if (history.data?.length && !history.data.some((r) => r.id === jobId)) {
      setJobId(history.data[0].id);
      setLiveStatus(history.data[0].status);
    }
  }, [history.data, jobId]);
  useEffect(() => {
    if (!catalog.data) return;
    if (!hashModeId) setHashModeId(catalog.data.hash_modes[0]?.id);
    if (!wordlistId) {
      setWordlistId(catalog.data.wordlists.find((w) => w.installed)?.id
        ?? catalog.data.wordlists[0]?.id);
    }
  }, [catalog.data, hashModeId, wordlistId]);
  useEffect(() => {
    const requestedMode = localStorage.getItem("oscp-workspace-hash-mode");
    if (requestedMode && catalog.data?.hash_modes.some((m) => m.id === requestedMode)) {
      setHashModeId(requestedMode);
      localStorage.removeItem("oscp-workspace-hash-mode");
    }
  }, [catalog.data]);
  useEffect(() => {
    const requestedHash = localStorage.getItem("oscp-workspace-hash-value");
    if (requestedHash && catalog.data) {
      setHashes(requestedHash);
      const detected = detectHashMode(requestedHash, catalog.data.hash_modes);
      if (detected) { setHashModeId(detected); setHashModeAuto(true); }
      localStorage.removeItem("oscp-workspace-hash-value");
    }
  }, [catalog.data]);

  const selected = history.data?.find((r) => r.id === jobId);
  const displayStatus = liveStatus ?? selected?.status;
  const selectedMode = catalog.data?.hash_modes.find((m) => m.id === hashModeId);
  const selectedWordlist = catalog.data?.wordlists.find((w) => w.id === wordlistId);
  const selectedWordlist2 = catalog.data?.wordlists.find((w) => w.id === wordlist2Id);
  const selectedAttackMode = ATTACK_MODES.find((m) => m.id === attackMode) ?? ATTACK_MODES[0];
  const wordlistReady = !selectedAttackMode.needsWordlist || !!selectedWordlist?.installed;
  const wordlist2Ready = !selectedAttackMode.needsWordlist2 || !!selectedWordlist2?.installed;
  const maskReady = !selectedAttackMode.needsMask || !!mask.trim();

  const onHashesChange = (value: string) => {
    setHashes(value);
    const detected = catalog.data && detectHashMode(value, catalog.data.hash_modes);
    if (detected) {
      setHashModeId(detected);
      setHashModeAuto(true);
    } else {
      setHashModeAuto(false);
    }
  };

  const uploadZip = async (file: File) => {
    // The native <input type="file"> is cleared right after picking (below)
    // so the same file can be re-selected without a no-op change event --
    // but that also blanks the browser's own "선택된 파일: X" text for the
    // whole upload, so this is the only place the filename is still shown.
    setZipError(""); setZipUploading(true); setZipFileName(file.name);
    try {
      const form = new FormData();
      form.append("file", file);
      const r = await fetch("/api/hash-cracking/zip2john", { method: "POST", body: form });
      const data = await r.json();
      if (!r.ok) throw new Error(data.detail || r.statusText);
      setHashes(data.hashes);
      setHashModeId(data.hash_mode_id);
      setHashModeAuto(true);
    } catch (reason) {
      setZipError(String(reason));
    } finally {
      setZipUploading(false);
    }
  };

  const createAndStart = async () => {
    if (!projectId || !targetId || !hashModeId || !hashes.trim()
      || !wordlistReady || !wordlist2Ready || !maskReady) return;
    setError(""); setPromoteMsg("");
    try {
      const created = await post<Job>("/hash-cracking", {
        project_id: projectId, target_id: targetId, label,
        hash_mode_id: hashModeId, hashes, attack_mode: attackMode,
        wordlist_id: selectedAttackMode.needsWordlist ? wordlistId : undefined,
        wordlist2_id: selectedAttackMode.needsWordlist2 ? wordlist2Id : undefined,
        rule_id: selectedAttackMode.needsRule ? (ruleId || undefined) : undefined,
        mask: selectedAttackMode.needsMask ? mask.trim() : undefined,
      });
      await post<Job>(`/hash-cracking/${created.id}/start`, {});
      setJobId(created.id);
      setLiveStatus("running");
      setHashes(""); setLabel(""); setHashModeAuto(false);
      await qc.invalidateQueries({ queryKey: ["hashCrackingJobs", targetId] });
    } catch (reason) { setError(String(reason)); }
  };
  const cancelJob = async (id: number) => {
    await post(`/hash-cracking/${id}/cancel`, {});
    await qc.invalidateQueries({ queryKey: ["hashCrackingJobs", targetId] });
  };
  const promote = async (cracked = promoteFor) => {
    if (!jobId || !cracked || (!initialCredentialId && !promoteUsername.trim())) return;
    try {
      await post(`/hash-cracking/${jobId}/promote`, {
        credential_id: initialCredentialId, username: promoteUsername.trim(), secret: cracked.plain,
        notes: `hashcat -m ${selected?.hash_mode ?? ""} 크랙 결과`,
      });
      setPromoteMsg(`${initialUsername || promoteUsername} Credential에 평문이 연결됨`);
      setPromoteFor(undefined); setPromoteUsername("");
    } catch (reason) { setPromoteMsg(String(reason)); }
  };
  const copyPlain = async (plain: string) => {
    await navigator.clipboard.writeText(plain);
    setCopiedPlain(plain);
    window.setTimeout(() => setCopiedPlain((current) => current === plain ? undefined : current), 1500);
  };
  const applyFormWidth = (width: number) => {
    const next = Math.min(480, Math.max(240, width));
    setFormWidth(next);
    localStorage.setItem("oscp-crack-form-width", String(next));
  };
  const beginFormResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    formResize.current = {x: event.clientX, width: formWidth};
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const resizeForm = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!event.currentTarget.hasPointerCapture(event.pointerId)) return;
    applyFormWidth(formResize.current.width + event.clientX - formResize.current.x);
  };
  const finishFormResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
  };
  const applyHistoryWidth = (width: number) => {
    const next = Math.min(420, Math.max(200, width));
    setHistoryWidth(next);
    localStorage.setItem("oscp-crack-history-width", String(next));
  };
  const beginHistoryResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    historyResize.current = {x: event.clientX, width: historyWidth};
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const resizeHistory = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!event.currentTarget.hasPointerCapture(event.pointerId)) return;
    // Dragging left grows the history panel since the handle sits on its
    // left edge, so the delta direction is inverted relative to the form
    // resize handle (which sits on its right edge and grows to the right).
    applyHistoryWidth(historyResize.current.width - (event.clientX - historyResize.current.x));
  };
  const finishHistoryResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
  };

  useEffect(() => {
    if (!jobId) return;
    setOutput("");
    const events = new EventSource(`/api/hash-cracking/${jobId}/events`);
    events.onmessage = (e) => {
      const item = JSON.parse(e.data);
      if (item.stream === "snapshot") setOutput(item.data);
      if (item.stream === "stdout") setOutput((v) => v + item.data);
      if (item.stream === "stderr") setOutput((v) => v + `[stderr] ${item.data}`);
      if (item.stream === "status" && terminal.includes(item.status)) {
        setLiveStatus(item.status);
        setOutput((v) => v + (item.error
          ? `\n[${item.status}] ${item.error}\n`
          : `\n[${item.status}${item.exit_code == null ? "" : ` · exit ${item.exit_code}`}` +
            `${item.cracked_count == null ? "" : ` · ${item.cracked_count}개 크랙`}]\n`));
        events.close();
        qc.invalidateQueries({ queryKey: ["hashCrackingJobs", targetId] });
        qc.invalidateQueries({ queryKey: ["hashCrackingOutput", jobId] });
      }
    };
    events.onerror = () => events.close();
    return () => events.close();
  }, [jobId, targetId, qc]);

  return (
    <div className={`crackPage${embedded ? " crackPage--embedded" : ""}`}>
      {embedded && <div className="graphWorkspaceHead"><b>HASH CRACKING</b>
        <button onClick={onBack}>← 그래프로 돌아가기</button></div>}
      {!embedded && <header>
        <div>
          <h1>Hash Cracking</h1>
        </div>
        <div className="crackSelectors">
          <select aria-label="프로젝트 선택" value={projectId || ""}
            onChange={(e) => setProjectId(+e.target.value)}>
            {projects.data?.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <select aria-label="대상 선택" value={targetId || ""}
            onChange={(e) => setTargetId(+e.target.value)}>
            {targets.data?.filter((t) => t.project_id === projectId).map((t) => (
              <option key={t.id} value={t.id}>{t.name} · {t.ip}</option>
            ))}
          </select>
        </div>
      </header>}
      {catalog.data && !catalog.data.hashcat_installed && (
        <div className="crackWarning">hashcat이 설치되어 있지 않습니다 (sudo apt install hashcat)</div>
      )}
      <main className="crackLayout" style={{
        "--crack-form-width": `${formWidth}px`,
        "--crack-history-width": `${historyWidth}px`,
      } as CSSProperties}>
        <section className="crackForm">
          {initialCredentialId && <div className="crackCredentialContext">
            <span>SOURCE CREDENTIAL</span>
            <strong>{initialUsername || "Credential"}</strong>
            <small>크랙 결과는 이 Credential에 자동 연결됩니다.</small>
          </div>}
          <label>
            라벨 (선택)
            <input value={label} onChange={(e) => setLabel(e.target.value)}
              placeholder="예: DC01 kerberoast" />
          </label>
          <label>
            해시 종류{hashModeAuto && <em className="crackAutoBadge">자동 감지됨</em>}
            <select value={hashModeId || ""}
              onChange={(e) => { setHashModeId(e.target.value); setHashModeAuto(false); }}>
              {catalog.data?.hash_modes.map((m) => (
                <option key={m.id} value={m.id}>{m.name} (-m {m.mode})</option>
              ))}
            </select>
          </label>
          {selectedMode && <code className="crackExample">{selectedMode.example}</code>}
          <label>
            zip 파일에서 해시 추출 (zip2john)
            <input type="file" accept=".zip" disabled={zipUploading}
              onChange={(e) => {
                const picked = e.target.files?.[0];
                e.target.value = "";
                if (picked) uploadZip(picked);
              }} />
          </label>
          {zipFileName && (
            <small>{zipFileName}{zipUploading ? " · zip2john 실행 중…" : ""}</small>
          )}
          {zipError && <ErrorState message={zipError} />}
          <label>
            해시 (한 줄에 하나씩 붙여넣기)
            <textarea rows={6} value={hashes} onChange={(e) => onHashesChange(e.target.value)}
              placeholder={selectedMode?.example} />
          </label>
          <label>
            공격 모드
            <select value={attackMode} onChange={(e) => setAttackMode(e.target.value)}>
              {ATTACK_MODES.map((m) => (
                <option key={m.id} value={m.id}>{m.name} (-a {m.id})</option>
              ))}
            </select>
          </label>
          {selectedAttackMode.needsWordlist && (
            <label>
              {selectedAttackMode.needsWordlist2 ? "워드리스트 1" : "워드리스트"}
              <select value={wordlistId || ""} onChange={(e) => setWordlistId(e.target.value)}>
                {catalog.data?.wordlists.map((w) => (
                  <option key={w.id} value={w.id} disabled={!w.installed}>
                    {w.name}{w.installed ? "" : ` (미설치${w.hint ? `: ${w.hint}` : ""})`}
                  </option>
                ))}
              </select>
            </label>
          )}
          {selectedAttackMode.needsWordlist && selectedWordlist && !selectedWordlist.installed && (
            <div className="crackWarning">
              선택한 워드리스트가 없습니다{selectedWordlist.hint ? `: ${selectedWordlist.hint}` : ""}
            </div>
          )}
          {selectedAttackMode.needsWordlist2 && (
            <label>
              워드리스트 2
              <select value={wordlist2Id || ""} onChange={(e) => setWordlist2Id(e.target.value)}>
                {catalog.data?.wordlists.map((w) => (
                  <option key={w.id} value={w.id} disabled={!w.installed}>
                    {w.name}{w.installed ? "" : ` (미설치${w.hint ? `: ${w.hint}` : ""})`}
                  </option>
                ))}
              </select>
            </label>
          )}
          {selectedAttackMode.needsMask && (
            <label>
              마스크
              <input value={mask} onChange={(e) => setMask(e.target.value)}
                placeholder="예: ?u?l?l?l?l?d?d?d" />
              <small className="crackMaskHint">
                ?l 소문자 · ?u 대문자 · ?d 숫자 · ?s 특수문자 · ?a 전체
              </small>
            </label>
          )}
          {selectedAttackMode.needsRule && (
            <label>
              규칙 파일 (선택)
              <select value={ruleId} onChange={(e) => setRuleId(e.target.value)}>
                <option value="">사용 안 함</option>
                {catalog.data?.rules.map((r) => (
                  <option key={r.id} value={r.id} disabled={!r.installed}>
                    {r.name}{r.installed ? "" : " (미설치)"}
                  </option>
                ))}
              </select>
            </label>
          )}
          {error && <ErrorState message={error} />}
          {displayStatus && (
            <div className="crackStatusBanner" role="status">
              <Badge status={displayStatus} />
              {selected && <small>작업 #{selected.id}</small>}
              {displayStatus === "running" && selected && (
                <button type="button" className="crackStatusBanner__cancel"
                  onClick={() => cancelJob(selected.id)}>중단</button>
              )}
            </div>
          )}
          <button type="button"
            disabled={!targetId || !hashModeId || !hashes.trim() || !wordlistReady
              || !wordlist2Ready || !maskReady || !catalog.data?.hashcat_installed}
            onClick={createAndStart}>
            크랙 시작
          </button>
          <div className="layoutResizeHandle crackFormResizeHandle"
            role="separator" aria-label="입력 폼 너비 조절" aria-orientation="vertical"
            aria-valuemin={240} aria-valuemax={480} aria-valuenow={formWidth}
            title="드래그하거나 마우스 휠·방향키로 너비 조절" tabIndex={0}
            onPointerDown={beginFormResize} onPointerMove={resizeForm}
            onPointerUp={finishFormResize} onPointerCancel={finishFormResize}
            onWheel={(event) => { event.preventDefault();
              applyFormWidth(formWidth + (event.deltaY < 0 ? 16 : -16)); }}
            onKeyDown={(event) => {
              if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
              event.preventDefault();
              if (event.key === "Home") applyFormWidth(240);
              else if (event.key === "End") applyFormWidth(480);
              else applyFormWidth(formWidth + (event.key === "ArrowRight" ? 16 : -16));
            }} />
        </section>
        <section className="crackMain">
          <DetachableTerminal id={`hash-output-${jobId || targetId || "idle"}`}
            label={`Hashcat ${jobId ? `#${jobId}` : "output"}`}
            commandContext={targetId && target ? {targetId, targetIp: target.ip} : undefined}>
          <div className="terminal crackTerminal">
            <div className={`terminalStatus${displayStatus ? ` terminalStatus--${displayStatus}` : ""}`}
              data-terminal-drag-handle title="드래그하여 터미널 분리">
              <span className="termDots" aria-hidden="true">
                <i className="termDot" /><i className="termDot termDot--yellow" />
                <i className="termDot termDot--green" />
              </span>
              <b>실시간 출력</b>
              <small>
                {displayStatus
                  ? `작업 #${jobId} · ${statusLabel[displayStatus] || displayStatus}`
                  : "작업 대기"}
              </small>
              {displayStatus === "running" && jobId && (
                <button type="button" onClick={() => cancelJob(jobId)}>중단</button>
              )}
            </div>
            <pre>{output}</pre>
          </div>
          </DetachableTerminal>
          {selected && terminal.includes(selected.status) && (
            <div className="crackResults">
              <b>크랙된 자격 증명 {outputQuery.data?.cracked.length ?? selected.cracked_count}건</b>
              {outputQuery.data?.cracked.map((item, index) => (
                <div key={index} className="crackResultRow">
                  <div className="crackResultPlain">
                    <b>{item.plain}</b>
                    <code title={item.hash}>{item.hash.slice(0, 40)}{item.hash.length > 40 ? "…" : ""}</code>
                  </div>
                  <div className="crackResultActions">
                    <button type="button" onClick={() => void copyPlain(item.plain)}>
                      {copiedPlain === item.plain ? "복사됨" : "복사"}
                    </button>
                    <button type="button"
                      onClick={() => initialCredentialId
                        ? void promote(item) : (setPromoteFor(item), setPromoteUsername(""))}>
                      {initialCredentialId ? `${initialUsername || "기존"}에 연결` : "Credential로 저장"}
                    </button>
                  </div>
                </div>
              ))}
              {!outputQuery.data?.cracked.length && <p className="empty">크랙된 항목이 없습니다.</p>}
              {selected.evidence_id && <a href="#evidence">Evidence 열림 →</a>}
              {promoteMsg && <span>{promoteMsg}</span>}
            </div>
          )}
          {promoteFor && (
            <div className="modal" role="presentation">
              <div role="dialog" aria-modal="true" aria-labelledby="crack-promote-title">
                <span>Credential 등록</span>
                <h2 id="crack-promote-title">{promoteFor.plain}</h2>
                <p>이 평문 비밀번호가 속한 사용자명을 입력하세요.</p>
                <input placeholder="사용자명" value={promoteUsername} autoFocus
                  onChange={(e) => setPromoteUsername(e.target.value)} />
                <footer>
                  <button onClick={() => setPromoteFor(undefined)}>취소</button>
                  <button disabled={!promoteUsername.trim()} onClick={() => void promote()}>저장</button>
                </footer>
              </div>
            </div>
          )}
        </section>
        <aside className="crackHistory">
          <div className="layoutResizeHandle crackHistoryResizeHandle"
            role="separator" aria-label="작업 이력 너비 조절" aria-orientation="vertical"
            aria-valuemin={200} aria-valuemax={420} aria-valuenow={historyWidth}
            title="드래그하거나 마우스 휠·방향키로 너비 조절" tabIndex={0}
            onPointerDown={beginHistoryResize} onPointerMove={resizeHistory}
            onPointerUp={finishHistoryResize} onPointerCancel={finishHistoryResize}
            onWheel={(event) => { event.preventDefault();
              applyHistoryWidth(historyWidth + (event.deltaY < 0 ? 16 : -16)); }}
            onKeyDown={(event) => {
              if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
              event.preventDefault();
              if (event.key === "Home") applyHistoryWidth(200);
              else if (event.key === "End") applyHistoryWidth(420);
              else applyHistoryWidth(historyWidth + (event.key === "ArrowLeft" ? 16 : -16));
            }} />
          <div className="panelTitle"><span>작업 이력</span></div>
          {history.isLoading && <LoadingState label="이력을 불러오는 중" />}
          {!history.isLoading && !history.data?.length && (
            <p className="empty">이 대상에서 실행한 크랙 작업이 없습니다.</p>
          )}
          {history.data?.map((r) => (
            <div key={r.id} role="button" tabIndex={0}
              className={`crackRow ${r.id === jobId ? "active" : ""}`}
              onClick={() => { setJobId(r.id); setLiveStatus(r.status); }}>
              <span><b>#{r.id} · {r.hash_type_name}</b>
                <em>{statusLabel[r.status] || r.status}</em></span>
              <small>{r.hash_count}개 해시 · {new Date(r.created_at).toLocaleString()}</small>
              {terminal.includes(r.status) && <small>크랙 {r.cracked_count}건</small>}
            </div>
          ))}
        </aside>
      </main>
    </div>
  );
}
