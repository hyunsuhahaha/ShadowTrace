import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { syncSelectedProject } from "./scanCenterModel";
import { ErrorState, LoadingState, statusCopy as statusLabel } from "./ui";
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

export default function HashCrackingWorkspace() {
  const qc = useQueryClient();
  const [projectId, setProjectId] = useState<number>();
  const [targetId, setTargetId] = useState<number>();
  const [label, setLabel] = useState("");
  const [hashModeId, setHashModeId] = useState<string>();
  const [hashModeAuto, setHashModeAuto] = useState(false);
  const [hashes, setHashes] = useState("");
  const [attackMode, setAttackMode] = useState("0");
  const [wordlistId, setWordlistId] = useState<string>();
  const [wordlist2Id, setWordlist2Id] = useState<string>();
  const [ruleId, setRuleId] = useState<string>("");
  const [mask, setMask] = useState("");
  const [jobId, setJobId] = useState<number>();
  const [error, setError] = useState("");
  const [output, setOutput] = useState("작업을 만들고 실행하면 실시간 출력이 표시됩니다.\n");
  const [promoteFor, setPromoteFor] = useState<Cracked>();
  const [promoteUsername, setPromoteUsername] = useState("");
  const [promoteMsg, setPromoteMsg] = useState("");

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
      setHashes(""); setLabel(""); setHashModeAuto(false);
      await qc.invalidateQueries({ queryKey: ["hashCrackingJobs", targetId] });
    } catch (reason) { setError(String(reason)); }
  };
  const cancelJob = async (id: number) => {
    await post(`/hash-cracking/${id}/cancel`, {});
    await qc.invalidateQueries({ queryKey: ["hashCrackingJobs", targetId] });
  };
  const promote = async () => {
    if (!jobId || !promoteFor || !promoteUsername.trim()) return;
    try {
      await post(`/hash-cracking/${jobId}/promote`, {
        username: promoteUsername.trim(), secret: promoteFor.plain,
        notes: `hashcat -m ${selected?.hash_mode ?? ""} 크랙 결과`,
      });
      setPromoteMsg(`${promoteUsername} 계정으로 Credential Store에 저장됨`);
      setPromoteFor(undefined); setPromoteUsername("");
    } catch (reason) { setPromoteMsg(String(reason)); }
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
    <div className="crackPage">
      <header>
        <div>
          <h1>Hash Cracking</h1>
          <p>secretsdump, Kerberoasting, ASREP roasting 등으로 확보한 해시를 hashcat으로
            오프라인 크랙합니다. 대상에 직접 접속하지 않습니다.</p>
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
      </header>
      {catalog.data && !catalog.data.hashcat_installed && (
        <div className="crackWarning">hashcat이 설치되어 있지 않습니다 (sudo apt install hashcat)</div>
      )}
      <main className="crackLayout">
        <section className="crackForm">
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
          <button type="button"
            disabled={!targetId || !hashModeId || !hashes.trim() || !wordlistReady
              || !wordlist2Ready || !maskReady || !catalog.data?.hashcat_installed}
            onClick={createAndStart}>
            크랙 시작
          </button>
        </section>
        <section className="crackMain">
          <div className="terminal crackTerminal">
            <div className={selected ? `terminalStatus terminalStatus--${selected.status}` : ""}>
              <span aria-hidden="true" />
              <b>실시간 출력</b>
              <small>
                {selected
                  ? `작업 #${selected.id} · ${statusLabel[selected.status] || selected.status}`
                  : "작업 대기"}
              </small>
              {selected?.status === "running" && (
                <button type="button" onClick={() => cancelJob(selected.id)}>중단</button>
              )}
            </div>
            <pre>{output}</pre>
          </div>
          {selected && terminal.includes(selected.status) && (
            <div className="crackResults">
              <b>크랙된 자격 증명 {outputQuery.data?.cracked.length ?? selected.cracked_count}건</b>
              {outputQuery.data?.cracked.map((item, index) => (
                <div key={index} className="crackResultRow">
                  <code title={item.hash}>{item.hash.slice(0, 40)}{item.hash.length > 40 ? "…" : ""}</code>
                  <b>{item.plain}</b>
                  <button type="button" onClick={() => { setPromoteFor(item); setPromoteUsername(""); }}>
                    Credential로 저장
                  </button>
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
                  <button disabled={!promoteUsername.trim()} onClick={promote}>저장</button>
                </footer>
              </div>
            </div>
          )}
        </section>
        <aside className="crackHistory">
          <div className="panelTitle"><span>작업 이력</span></div>
          {history.isLoading && <LoadingState label="이력을 불러오는 중" />}
          {!history.isLoading && !history.data?.length && (
            <p className="empty">이 대상에서 실행한 크랙 작업이 없습니다.</p>
          )}
          {history.data?.map((r) => (
            <div key={r.id} role="button" tabIndex={0}
              className={`crackRow ${r.id === jobId ? "active" : ""}`}
              onClick={() => setJobId(r.id)}>
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
