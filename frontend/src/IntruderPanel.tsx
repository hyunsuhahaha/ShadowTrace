import { useEffect, useMemo, useRef, useState } from "react";
import {
  type AttackType, type PayloadPosition, parseCandidates,
  previewCombinations, requestCount,
} from "./credentialCandidates";

type Result = {
  exchange_id: number;
  position_values: Record<string, string>;
  status_code?: number;
  response_length: number;
  word_count: number;
  line_count: number;
  duration_ms: number;
  redirect: string;
  content_type: string;
  string_matches: boolean[];
  regex_matches: boolean[];
  review_status: string;
  error: string;
};
type SavedSet = { name: string; values: string[]; sensitive: boolean };
type Progress = { status: string; completed: number; total: number };
const SETS_KEY = "oscp-intruder-candidate-sets";

const newPosition = (index: number): PayloadPosition => ({
  name: `position_${index}`,
  candidates: [],
  rules: [],
});

export default function IntruderPanel({ requestId, timeout, projectId, targetId, serviceId }: {
  requestId?: number; timeout: number; projectId?: number; targetId?: number; serviceId?: number;
}) {
  const [attackType, setAttackType] = useState<AttackType>("sniper");
  const [positions, setPositions] = useState<PayloadPosition[]>([newPosition(1)]);
  const [inputs, setInputs] = useState([""]);
  const [ruleInputs, setRuleInputs] = useState(["[]"]);
  const [deduplicate, setDeduplicate] = useState(true);
  const [maxRequests, setMaxRequests] = useState(20);
  const [delayMs, setDelayMs] = useState(500);
  const [retryCount, setRetryCount] = useState(0);
  const [stopStatuses, setStopStatuses] = useState("");
  const [stopString, setStopString] = useState("");
  const [grepStrings, setGrepStrings] = useState("");
  const [grepRegexes, setGrepRegexes] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [results, setResults] = useState<Result[]>([]);
  const [error, setError] = useState("");
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<Progress>();
  const [filter, setFilter] = useState("");
  const [maskValues, setMaskValues] = useState(true);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [savedSets, setSavedSets] = useState<SavedSet[]>(() => {
    try { return JSON.parse(localStorage.getItem(SETS_KEY) || "[]"); } catch { return []; }
  });
  const [setName, setSetName] = useState("");
  const runId = useRef("");
  const count = useMemo(() => requestCount(attackType, positions), [attackType, positions]);
  const preview = useMemo(
    () => previewCombinations(attackType, positions, 5),
    [attackType, positions],
  );
  const visibleResults = useMemo(() => results.filter((result) =>
    !filter || JSON.stringify(result).toLowerCase().includes(filter.toLowerCase()),
  ), [filter, results]);
  useEffect(() => {
    if (!running || !runId.current) return;
    const timer = setInterval(async () => {
      const response = await fetch(`/api/web/intruder/${runId.current}`);
      if (response.ok) setProgress(await response.json());
    }, 350);
    return () => clearInterval(timer);
  }, [running]);
  const saveSets = (sets: SavedSet[]) => {
    setSavedSets(sets);
    localStorage.setItem(SETS_KEY, JSON.stringify(sets));
  };
  const updatePosition = (index: number, patch: Partial<PayloadPosition>) =>
    setPositions((current) => current.map((item, i) => i === index ? { ...item, ...patch } : item));
  const updateCandidates = (index: number, text: string) => {
    setInputs((current) => current.map((item, i) => i === index ? text : item));
    updatePosition(index, { candidates: parseCandidates(text, deduplicate) });
  };
  const add = () => {
    setPositions((current) => [...current, newPosition(current.length + 1)]);
    setInputs((current) => [...current, ""]);
    setRuleInputs((current) => [...current, "[]"]);
    setConfirmed(false);
  };
  const remove = (index: number) => {
    setPositions((current) => current.filter((_, i) => i !== index));
    setInputs((current) => current.filter((_, i) => i !== index));
    setRuleInputs((current) => current.filter((_, i) => i !== index));
    setConfirmed(false);
  };
  const run = async () => {
    if (!requestId) return setError("먼저 요청을 저장하세요.");
    runId.current = crypto.randomUUID();
    setRunning(true); setError(""); setResults([]); setSelected(new Set());
    setProgress({ status: "running", completed: 0, total: count });
    try {
      const response = await fetch(`/api/web/requests/${requestId}/intruder`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          run_id: runId.current,
          attack_type: attackType,
          positions,
          max_requests: maxRequests,
          delay_ms: delayMs,
          grep_strings: parseCandidates(grepStrings),
          grep_regexes: parseCandidates(grepRegexes),
          retry_count: retryCount,
          stop_status_codes: parseCandidates(stopStatuses).map(Number).filter(Number.isInteger),
          stop_string: stopString,
          confirmed,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || response.statusText);
      setResults(data.results);
      setProgress((current) => ({ status: data.status, completed: data.request_count,
        total: current?.total || data.request_count }));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setRunning(false); setConfirmed(false);
    }
  };
  const control = async (action: "pause" | "resume" | "stop") => {
    if (!runId.current) return;
    const response = await fetch(`/api/web/intruder/${runId.current}/${action}`, { method: "POST" });
    if (response.ok) setProgress(await response.json());
  };
  const download = (format: "json" | "csv") => {
    const values = selected.size ? results.filter((item) => selected.has(item.exchange_id)) : results;
    const content = format === "json" ? JSON.stringify(values, null, 2) :
      ["request,status,length,duration_ms,positions",
        ...values.map((item, index) => [
          index + 1, item.status_code || "ERROR", item.response_length, item.duration_ms,
          JSON.stringify(item.position_values),
        ].map((value) => `"${String(value).replaceAll('"', '""')}"`).join(","))].join("\n");
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([content], {
      type: format === "json" ? "application/json" : "text/csv",
    }));
    link.download = `intruder-results.${format}`;
    link.click(); URL.revokeObjectURL(link.href);
  };
  const selectedResults = () =>
    selected.size ? results.filter((item) => selected.has(item.exchange_id)) : results;
  const saveSelectedCandidates = () => {
    const values = selectedResults().flatMap((item) => Object.values(item.position_values));
    const name = setName.trim() || `결과 후보 ${new Date().toLocaleString()}`;
    saveSets([...savedSets.filter((item) => item.name !== name), {
      name, values: [...new Set(values)], sensitive: true,
    }]);
    setSetName("");
  };
  const linkEvidence = async () => {
    if (!projectId || !targetId || !selectedResults().length) return;
    const data = new FormData();
    data.append("project_id", String(projectId)); data.append("target_id", String(targetId));
    if (serviceId) data.append("service_id", String(serviceId));
    data.append("title", `Intruder 응답 검토 ${new Date().toLocaleString()}`);
    data.append("description", "사용자가 선택한 Web Testing Intruder 결과");
    data.append("kind", "http"); data.append("source_type", "http_exchange");
    data.append("source_id", String(selectedResults()[0].exchange_id));
    data.append("sensitivity", "sensitive");
    data.append("file", new File(
      [JSON.stringify(selectedResults(), null, 2)], "intruder-results.json",
      { type: "application/json" },
    ));
    const response = await fetch("/api/evidence/upload", { method: "POST", body: data });
    if (!response.ok) throw new Error((await response.json()).detail || response.statusText);
  };
  return (
    <section className="intruderPanel">
      <header>
        <div><span>Request variation desk</span><h2>Intruder</h2>
          <p>요청 위치, 후보, 실행 제한과 응답 차이를 한 화면에서 검토합니다.</p></div>
        <div className="intruderEstimate"><small>예상 요청</small><strong>{count}</strong>
          <small>최대 약 {Math.ceil(count * (delayMs + timeout * 1000) / 1000)}초</small></div>
      </header>
      <p>
        저장 요청의 URL·Query·Header·Cookie·Body 값에 <code>{"{{position_1}}"}</code>처럼
        마커를 넣으세요. 계정 잠금과 서비스 부하를 먼저 검토하세요.
      </p>
      <div className="intruderControls">
        <label>공격 유형
          <select value={attackType} onChange={(event) => { setAttackType(event.target.value as AttackType); setConfirmed(false); }}>
            <option value="sniper">Sniper · 위치를 하나씩 변경</option>
            <option value="battering_ram">Battering ram · 동일 값 동시 적용</option>
            <option value="pitchfork">Pitchfork · 같은 인덱스 조합</option>
            <option value="cluster_bomb">Cluster bomb · 모든 조합</option>
          </select>
        </label>
        <label>최대 요청 수<input type="number" min="1" max="100" value={maxRequests}
          onChange={(event) => { setMaxRequests(+event.target.value); setConfirmed(false); }} /></label>
        <label>요청 간 지연(ms)<input type="number" min="100" value={delayMs}
          onChange={(event) => setDelayMs(+event.target.value)} /></label>
        <label>오류 재시도<select value={retryCount} onChange={(event) => setRetryCount(+event.target.value)}>
          <option value="0">재시도 없음</option><option value="1">1회</option><option value="2">2회</option>
        </select></label>
        <label className="check"><input type="checkbox" checked={deduplicate}
          onChange={(event) => setDeduplicate(event.target.checked)} /> 중복 제거</label>
      </div>
      <div className="intruderStopRules">
        <label>중단할 Status code<input value={stopStatuses} placeholder="401, 429, 503"
          onChange={(event) => setStopStatuses(event.target.value)} /></label>
        <label>발견 시 중단할 문자열<input value={stopString} placeholder="선택 사항"
          onChange={(event) => setStopString(event.target.value)} /></label>
      </div>
      {attackType === "pitchfork" &&
        new Set(positions.map((position) => position.candidates.length)).size > 1 &&
        <div className="intruderWarning">목록 길이가 다릅니다. 짧은 목록 길이에서 종료합니다.</div>}
      {positions.map((position, index) => (
        <article className="payloadPosition" key={index}>
          <label>위치 이름<input value={position.name}
            onChange={(event) => { updatePosition(index, { name: event.target.value }); setConfirmed(false); }} /></label>
          <label>후보 값 · {position.candidates.length}개
            <textarea value={inputs[index]} placeholder={"한 줄 또는 쉼표로 구분 · 숫자 범위 1..20\n입력 순서를 유지합니다."}
              onChange={(event) => { updateCandidates(index, event.target.value); setConfirmed(false); }} />
          </label>
          <label>처리 규칙 JSON · 순서대로 적용
            <textarea value={ruleInputs[index]} placeholder='[{"type":"prefix","value":"id-"}]'
              onChange={(event) => {
                const value = event.target.value;
                setRuleInputs((current) => current.map((item, i) => i === index ? value : item));
                try {
                  updatePosition(index, { rules: JSON.parse(value) });
                  setError("");
                } catch {
                  setError("처리 규칙 JSON 형식을 확인하세요.");
                }
                setConfirmed(false);
              }} />
          </label>
          <label className="fileButton">텍스트 파일 불러오기<input type="file" accept=".txt,text/plain"
            onChange={async (event) => {
              const file = event.target.files?.[0];
              if (file) updateCandidates(index, await file.text());
            }} /></label>
          <label>저장 후보 세트<select defaultValue="" onChange={(event) => {
            const set = savedSets.find((item) => item.name === event.target.value);
            if (set) updateCandidates(index, set.values.join("\n"));
          }}><option value="">선택</option>{savedSets.map((set) =>
            <option key={set.name} value={set.name}>{set.name} · {set.values.length}개</option>)}</select></label>
          <button type="button" disabled={positions.length === 1} onClick={() => remove(index)}>위치 삭제</button>
        </article>
      ))}
      <button type="button" onClick={add}>+ 변형 위치 추가</button>
      <div className="candidateSetBar">
        <input value={setName} placeholder="현재 첫 번째 후보 목록 이름"
          onChange={(event) => setSetName(event.target.value)} />
        <button disabled={!setName.trim() || !positions[0]?.candidates.length} onClick={() => {
          saveSets([...savedSets.filter((item) => item.name !== setName.trim()), {
            name: setName.trim(), values: positions[0].candidates, sensitive: true,
          }]); setSetName("");
        }}>후보 세트 저장</button>
        {savedSets.map((set) => <button className="savedSet" key={set.name}
          onClick={() => saveSets(savedSets.filter((item) => item.name !== set.name))}>
          {set.name} 삭제</button>)}
      </div>
      <div className="grepControls">
        <label>찾을 문자열<textarea value={grepStrings} onChange={(event) => setGrepStrings(event.target.value)} /></label>
        <label>찾을 정규식<textarea value={grepRegexes} onChange={(event) => setGrepRegexes(event.target.value)} /></label>
      </div>
      <div className="requestPreview">
        <b>조합 미리보기 · 최대 5개</b>
        <pre>{preview.length ? JSON.stringify(preview, null, 2) : "후보를 입력하세요."}</pre>
      </div>
      {count > maxRequests && <div className="intruderWarning">
        예상 요청 수가 승인 상한을 초과합니다. 실행이 차단됩니다.
      </div>}
      <label className="intruderApproval"><input type="checkbox" checked={confirmed}
        onChange={(event) => setConfirmed(event.target.checked)} />
        최종 요청, 대상 소유·허가 범위, 요청 수와 잠금·부하 위험을 확인했습니다.
      </label>
      {error && <div className="webError">{error}</div>}
      <button disabled={!confirmed || !count || count > maxRequests || running} onClick={run}>
        {running ? "실행 중…" : "승인한 변형 실행"}
      </button>
      {progress && <div className="intruderProgress" role="status" aria-live="polite">
        <div><b>{progress.status === "paused" ? "일시정지" :
          progress.status === "stopped" ? "중단됨" :
          progress.status === "completed" ? "완료" : "요청 실행 중"}</b>
          <span>{progress.completed} / {progress.total}</span></div>
        <progress max={progress.total || 1} value={progress.completed} />
        {running && <div>
          <button disabled={progress.status === "paused"} onClick={() => control("pause")}>일시정지</button>
          <button disabled={progress.status !== "paused"} onClick={() => control("resume")}>재개</button>
          <button className="danger" onClick={() => control("stop")}>즉시 중지</button>
        </div>}
      </div>}
      {!!results.length && <div className="intruderResults">
        <header><div><b>응답 검토</b><span>{visibleResults.length}개 표시</span></div>
          <input aria-label="결과 필터" value={filter} placeholder="Status, 값, Content-Type 필터"
            onChange={(event) => setFilter(event.target.value)} />
          <label><input type="checkbox" checked={maskValues}
            onChange={(event) => setMaskValues(event.target.checked)} /> 민감 값 마스킹</label>
          <button onClick={saveSelectedCandidates}>후보로 저장</button>
          <button disabled={!projectId || !targetId} onClick={() => linkEvidence()
            .then(() => setError("")).catch((reason) => setError(String(reason)))}>Evidence 연결</button>
          <button onClick={() => download("json")}>JSON</button><button onClick={() => download("csv")}>CSV</button>
        </header>
        <table><thead><tr><th></th><th>#</th><th>위치 값</th><th>Status</th><th>길이</th><th>기준 차이</th><th>단어/줄</th><th>시간</th><th>Match</th><th>검토</th></tr></thead>
          <tbody>{visibleResults.map((result, index) => <tr key={result.exchange_id}>
            <td><input type="checkbox" checked={selected.has(result.exchange_id)} onChange={(event) =>
              setSelected((current) => { const next = new Set(current);
                event.target.checked ? next.add(result.exchange_id) : next.delete(result.exchange_id); return next; })} /></td>
            <td>{index + 1}</td><td><code>{maskValues ? Object.keys(result.position_values)
              .map((key) => `${key}=••••`).join(" · ") : JSON.stringify(result.position_values)}</code></td>
            <td>{result.error ? "ERROR" : result.status_code}</td><td>{result.response_length}</td>
            <td>{result.response_length - results[0].response_length > 0 ? "+" : ""}
              {result.response_length - results[0].response_length}</td>
            <td>{result.word_count}/{result.line_count}</td><td>{result.duration_ms} ms</td>
            <td>{[...result.string_matches, ...result.regex_matches].filter(Boolean).length || "—"}</td>
            <td><select defaultValue={result.review_status}><option>검토 필요</option>
              <option>사용자가 확인함</option><option>무시함</option></select></td>
          </tr>)}</tbody>
        </table>
      </div>}
    </section>
  );
}
