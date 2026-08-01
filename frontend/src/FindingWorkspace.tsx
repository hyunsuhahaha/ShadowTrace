import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge, Button, EmptyState, ErrorState, LoadingState } from "./ui";
import EvidenceImageEditor from "./EvidenceImageEditor";
import "./finding-advanced.css";
import "./finding-responsive.css";

type Link = {
  evidence_id: number; caption: string; display_order: number;
  include_client: boolean; include_internal: boolean;
  is_primary: boolean; phase: "BEFORE" | "AFTER";
};
type Finding = {
  id?: number; title: string; category: string; target_id: number | null;
  service_id: number | null; target_ids: number[]; service_ids: number[];
  cvss_vector: string; cvss_score?: string;
  severity?: string; final_risk: string; risk_override_reason: string;
  status: string; disclosure: string; summary: string; description: string;
  business_impact: string; technical_impact: string; reproduction_steps: string;
  recommendation: string; internal_notes: string; sort_priority: number;
  tags: string[]; references: string[]; evidence: Link[]; retests?: Retest[];
};
type Retest = { id: number; tested_at: string; tester: string; result: string;
  remediated: boolean; notes: string; before_evidence_ids: number[]; after_evidence_ids: number[] };
type Evidence = { id: number; title: string; kind: string; sensitivity: string; target_id: number };
type Target = { id: number; name: string; ip: string; services?: Service[] };
type Service = { id: number; port: number; protocol: string; name: string; target_id: number };
type Template = { id: number; title: string; category: string; severity: string; use_count: number; last_used_at?: string };

const risks = ["Critical", "High", "Medium", "Low", "Informational"];
const statuses = ["Draft", "Confirmed", "Needs Review", "Remediated", "Accepted Risk", "False Positive"];
const empty = (): Finding => ({
  title: "", category: "", target_id: null, service_id: null,
  target_ids: [], service_ids: [],
  cvss_vector: "", final_risk: "Informational", risk_override_reason: "",
  status: "Draft", disclosure: "BOTH", summary: "", description: "",
  business_impact: "", technical_impact: "", reproduction_steps: "",
  recommendation: "", internal_notes: "", sort_priority: 0, tags: [],
  references: [], evidence: [],
});
const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch("/api" + path, init);
  if (!response.ok) throw new Error((await response.json()).detail || response.statusText);
  return response.status === 204 ? (undefined as T) : response.json();
};
const riskClass = (risk: string) => `riskTone riskTone--${risk.toLowerCase()}`;
const cvssMetrics: Record<string, { label: string; values: [string, string][] }> = {
  AV: { label: "Attack Vector", values: [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]] },
  AC: { label: "Complexity", values: [["L", "Low"], ["H", "High"]] },
  PR: { label: "Privileges", values: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  UI: { label: "User Interaction", values: [["N", "None"], ["R", "Required"]] },
  S: { label: "Scope", values: [["U", "Unchanged"], ["C", "Changed"]] },
  C: { label: "Confidentiality", values: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  I: { label: "Integrity", values: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  A: { label: "Availability", values: [["N", "None"], ["L", "Low"], ["H", "High"]] },
};
const parseVector = (vector: string) => Object.fromEntries(vector.split("/").slice(1)
  .filter((part) => part.includes(":")).map((part) => part.split(":")));

export default function FindingWorkspace({ projectId }: { projectId?: number }) {
  const qc = useQueryClient();
  const [selectedId, setSelectedId] = useState<number>();
  const [draft, setDraft] = useState<Finding>(empty);
  const [baseline, setBaseline] = useState(JSON.stringify(empty()));
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [templateQuery, setTemplateQuery] = useState("");
  const [activeSection, setActiveSection] = useState("overview");
  const [message, setMessage] = useState<{ kind: "error" | "success"; text: string }>();
  const [saving, setSaving] = useState(false);
  const [cvssChecking, setCvssChecking] = useState(false);
  const [retest, setRetest] = useState({ tester: "", result: "Still Vulnerable", remediated: false, notes: "" });
  const [retestSaving, setRetestSaving] = useState(false);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [bulkStatus, setBulkStatus] = useState("Confirmed");
  const [editingEvidence, setEditingEvidence] = useState<Evidence>();
  const [evidenceOpen, setEvidenceOpen] = useState(false);

  const findings = useQuery({
    queryKey: ["findings", projectId, query, severity, status],
    queryFn: () => api<Finding[]>(`/findings?project_id=${projectId}&q=${encodeURIComponent(query)}&severity=${severity}&status=${encodeURIComponent(status)}`),
    enabled: !!projectId,
  });
  const evidence = useQuery({
    queryKey: ["projectEvidence", projectId],
    queryFn: () => api<Evidence[]>(`/evidence?project_id=${projectId}`),
    enabled: !!projectId,
  });
  const targets = useQuery({
    queryKey: ["targets", projectId],
    queryFn: () => api<Target[]>(`/targets?project_id=${projectId}`),
    enabled: !!projectId,
  });
  const templates = useQuery({
    queryKey: ["findingTemplates", templateQuery],
    queryFn: () => api<Template[]>(`/finding-templates?q=${encodeURIComponent(templateQuery)}`),
  });
  const summary = useQuery({
    queryKey: ["findingSummary", projectId],
    queryFn: () => api<any>(`/projects/${projectId}/finding-summary`),
    enabled: !!projectId,
  });
  const dirty = JSON.stringify(draft) !== baseline;
  const selectedTarget = targets.data?.find((target) => target.id === draft.target_id);
  const servicesQuery = useQuery({
    queryKey: ["findingServices", draft.target_ids],
    queryFn: async () => (await Promise.all(draft.target_ids.map((id) =>
      api<Service[]>(`/targets/${id}/services`)))).flat(),
    enabled: !!draft.target_ids.length,
  });
  const services = useMemo(() => servicesQuery.data || [], [servicesQuery.data]);
  const linkedEvidence = draft.evidence
    .map((link) => ({ link, item: evidence.data?.find((item) => item.id === link.evidence_id) }))
    .filter((row) => row.item);
  const visibleEvidence = evidence.data?.filter((item) =>
    (!draft.target_ids.length || draft.target_ids.includes(item.target_id)) &&
    !draft.evidence.some((link) => link.evidence_id === item.id)) || [];

  useEffect(() => {
    setSelectedId(undefined);
    setDraft(empty());
    setBaseline(JSON.stringify(empty()));
    setMessage(undefined);
  }, [projectId]);
  useEffect(() => {
    if (!selectedId && !dirty && findings.data?.[0]) choose(findings.data[0]);
  }, [findings.data, selectedId]);

  const choose = (finding: Finding) => {
    if (dirty && !confirm("저장하지 않은 변경사항을 버리고 다른 Finding을 열까요?")) return;
    setSelectedId(finding.id);
    setDraft(finding);
    setBaseline(JSON.stringify(finding));
    setMessage(undefined);
    setActiveSection("overview");
  };
  const startNew = () => {
    if (dirty && !confirm("저장하지 않은 변경사항을 버리고 새 Finding을 만들까요?")) return;
    const next = empty();
    setSelectedId(undefined); setDraft(next); setBaseline(JSON.stringify(next));
    setMessage(undefined); setActiveSection("overview");
  };
  const patch = (values: Partial<Finding>) => setDraft((current) => ({ ...current, ...values }));

  const checkCvss = async () => {
    if (!draft.cvss_vector) {
      patch({ final_risk: "Informational" });
      return;
    }
    setCvssChecking(true);
    try {
      const result = await api<{ score: number; severity: string }>(`/cvss?vector=${encodeURIComponent(draft.cvss_vector)}`);
      patch({ cvss_score: String(result.score), severity: result.severity,
        final_risk: draft.risk_override_reason ? draft.final_risk : result.severity });
      setMessage({ kind: "success", text: `CVSS ${result.score} · ${result.severity}로 계산했습니다.` });
    } catch (error) {
      setMessage({ kind: "error", text: String(error) });
    } finally { setCvssChecking(false); }
  };
  const setMetric = (metric: string, value: string) => {
    const values = { ...parseVector(draft.cvss_vector), [metric]: value };
    patch({ cvss_vector: "CVSS:3.1/" + Object.keys(cvssMetrics)
      .filter((key) => values[key]).map((key) => `${key}:${values[key]}`).join("/"),
      cvss_score: undefined });
  };
  const applyBulkStatus = async () => {
    if (!selectedIds.length || !confirm(`${selectedIds.length}개 Finding 상태를 ${bulkStatus}(으)로 변경할까요?`)) return;
    try {
      await api(`/findings/bulk-status?project_id=${projectId}&status=${encodeURIComponent(bulkStatus)}`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(selectedIds),
      });
      setSelectedIds([]); setMessage({ kind: "success", text: "선택한 Finding 상태를 변경했습니다." });
      qc.invalidateQueries({ queryKey: ["findings"] }); qc.invalidateQueries({ queryKey: ["findingSummary"] });
    } catch (error) { setMessage({ kind: "error", text: String(error) }); }
  };

  const save = async () => {
    if (!draft.title.trim()) {
      setMessage({ kind: "error", text: "Finding 제목을 입력하세요." }); return;
    }
    if (draft.cvss_vector && !draft.cvss_score) {
      setMessage({ kind: "error", text: "CVSS 벡터를 검증한 뒤 저장하세요." }); return;
    }
    setSaving(true); setMessage(undefined);
    try {
      const row = await api<Finding>(selectedId ? `/findings/${selectedId}` : "/findings", {
        method: selectedId ? "PUT" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...draft, project_id: projectId }),
      });
      setSelectedId(row.id); setDraft(row); setBaseline(JSON.stringify(row));
      setMessage({ kind: "success", text: "Finding을 저장했습니다." });
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["findingSummary"] });
    } catch (error) {
      setMessage({ kind: "error", text: String(error) });
    } finally { setSaving(false); }
  };

  const applyTemplate = async (templateId: number) => {
    if (dirty && !confirm("현재 편집 내용을 버리고 템플릿으로 새 Finding을 만들까요?")) return;
    try {
      const row = await api<Finding>(`/finding-templates/${templateId}/apply?project_id=${projectId}`, { method: "POST" });
      setSelectedId(row.id); setDraft(row); setBaseline(JSON.stringify(row));
      setMessage({ kind: "success", text: "템플릿 스냅샷으로 Finding을 만들었습니다." });
      qc.invalidateQueries({ queryKey: ["findings"] });
    } catch (error) { setMessage({ kind: "error", text: String(error) }); }
  };
  const addRetest = async () => {
    if (!selectedId) { setMessage({ kind: "error", text: "Finding을 먼저 저장하세요." }); return; }
    if (!retest.tester.trim()) { setMessage({ kind: "error", text: "재검증 담당자를 입력하세요." }); return; }
    setRetestSaving(true);
    try {
      await api(`/findings/${selectedId}/retests`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...retest,
          before_evidence_ids: draft.evidence.filter((link) => link.phase === "BEFORE").map((link) => link.evidence_id),
          after_evidence_ids: draft.evidence.filter((link) => link.phase === "AFTER").map((link) => link.evidence_id),
        }),
      });
      const refreshed = await api<Finding>(`/findings/${selectedId}`);
      setDraft(refreshed); setBaseline(JSON.stringify(refreshed));
      setRetest({ tester: "", result: "Still Vulnerable", remediated: false, notes: "" });
      setMessage({ kind: "success", text: "재검증 이력을 추가했습니다." });
      qc.invalidateQueries({ queryKey: ["findings"] });
    } catch (error) { setMessage({ kind: "error", text: String(error) }); }
    finally { setRetestSaving(false); }
  };

  const addEvidence = (item: Evidence) => patch({ evidence: [...draft.evidence, {
    evidence_id: item.id, caption: item.title, display_order: draft.evidence.length,
    include_client: item.sensitivity === "normal", include_internal: true,
    is_primary: !draft.evidence.length, phase: "BEFORE",
  }] });
  const updateLink = (id: number, values: Partial<Link>) => patch({
    evidence: draft.evidence.map((link) => link.evidence_id === id ? { ...link, ...values } : link),
  });
  const removeLink = (id: number) => patch({
    evidence: draft.evidence.filter((link) => link.evidence_id !== id)
      .map((link, index) => ({ ...link, display_order: index })),
  });
  const moveLink = (id: number, direction: -1 | 1) => {
    const rows = [...draft.evidence];
    const index = rows.findIndex((link) => link.evidence_id === id);
    const next = index + direction;
    if (next < 0 || next >= rows.length) return;
    [rows[index], rows[next]] = [rows[next], rows[index]];
    patch({ evidence: rows.map((link, position) => ({ ...link, display_order: position })) });
  };

  if (!projectId) return <EmptyState title="프로젝트가 필요합니다" description="상단에서 프로젝트를 선택하거나 새 프로젝트를 만드세요." />;
  return <main className="findingWorkspace">
    <aside className="findingIndex" aria-label="Finding 목록">
      <div className="panelHeading">
        <div><span>TRIAGE QUEUE</span><h2>Findings</h2></div>
        <Button variant="primary" onClick={startNew}>새 Finding</Button>
      </div>
      <div className="findingFilters">
        <label className="searchField"><span>검색</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="제목 또는 키워드" /></label>
        <select aria-label="위험도 필터" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">모든 위험도</option>{risks.map((risk) => <option key={risk}>{risk}</option>)}
        </select>
        <select aria-label="상태 필터" value={status} onChange={(event) => setStatus(event.target.value)}>
          <option value="">모든 상태</option>{statuses.map((value) => <option key={value}>{value}</option>)}
        </select>
      </div>
      {selectedIds.length > 0 && <div className="bulkBar"><strong>{selectedIds.length}개 선택</strong><select value={bulkStatus} onChange={(event) => setBulkStatus(event.target.value)}>{statuses.map((value) => <option key={value}>{value}</option>)}</select><Button onClick={applyBulkStatus}>상태 변경</Button><button onClick={() => setSelectedIds([])}>취소</button></div>}
      <div className="findingList">
        {findings.isLoading && <LoadingState label="Finding을 불러오는 중" />}
        {findings.error && <ErrorState message={String(findings.error)} />}
        {!findings.isLoading && !findings.data?.length && <EmptyState title="조건에 맞는 Finding이 없습니다" description="필터를 지우거나 첫 Finding을 작성하세요." />}
        {findings.data?.map((finding) => <button key={finding.id} className={selectedId === finding.id ? "active" : ""} onClick={() => choose(finding)}>
          <input aria-label={`${finding.title} 선택`} type="checkbox" checked={selectedIds.includes(finding.id!)} onClick={(event) => event.stopPropagation()} onChange={(event) => setSelectedIds((current) => event.target.checked ? [...current, finding.id!] : current.filter((id) => id !== finding.id))} />
          <span className={riskClass(finding.final_risk)}>{finding.final_risk}</span>
          <strong>{finding.title}</strong>
          <small>{finding.category || "분류 없음"} · {finding.status}</small>
          <em>#{finding.id}</em>
        </button>)}
      </div>
      <details className="templateLibrary">
        <summary><span>Finding 라이브러리</span><small>{templates.data?.length || 0}</small></summary>
        <input aria-label="템플릿 검색" value={templateQuery} onChange={(event) => setTemplateQuery(event.target.value)} placeholder="템플릿 검색" />
        {templates.data?.map((template) => <button key={template.id} onClick={() => applyTemplate(template.id)}>
          <span className={riskClass(template.severity)}>{template.severity}</span>
          <strong>{template.title}</strong><small>{template.category || "분류 없음"} · {template.use_count}회 사용</small>
        </button>)}
      </details>
    </aside>

    <section className="findingEditor">
      <header className="editorHeader">
        <div>
          <span>{selectedId ? `FINDING #${selectedId}` : "NEW FINDING"}</span>
          <h1>{draft.title || "제목 없는 Finding"}</h1>
          <p>{draft.target_id ? `${selectedTarget?.name || "대상"} · ${draft.final_risk}` : "영향 대상을 연결하고 위험도를 평가하세요."}</p>
        </div>
        <div className="saveState">
          <span className={dirty ? "dirty" : ""}>{dirty ? "저장되지 않은 변경" : "저장됨"}</span>
          <Button className="evidenceDrawerButton" onClick={() => setEvidenceOpen(true)}>Evidence {draft.evidence.length}</Button>
          <Button variant="primary" disabled={saving || !dirty} onClick={save}>{saving ? "저장 중…" : "저장"}</Button>
        </div>
      </header>
      {summary.data && <section className="riskStrip" aria-label="프로젝트 위험도 요약">
        <div><span>전체</span><strong>{summary.data.total}</strong></div>
        {risks.map((risk) => <div key={risk} className={riskClass(risk)}><span>{risk}</span><strong>{summary.data.severity[risk]}</strong></div>)}
        <div><span>미완료</span><strong>{summary.data.open}</strong></div>
      </section>}
      <nav className="editorSections" aria-label="Finding 편집 섹션">
        {[["overview", "개요"], ["risk", "위험도"], ["details", "상세 및 영향"], ["remediation", "재현 및 권고"], ["retest", "재검증"]].map(([key, label]) =>
          <button key={key} aria-current={activeSection === key ? "page" : undefined} onClick={() => { setActiveSection(key); document.getElementById(`finding-${key}`)?.scrollIntoView(); }}>{label}</button>)}
      </nav>
      <div className="editorScroll">
        {message && <div className={`inlineNotice inlineNotice--${message.kind}`} role={message.kind === "error" ? "alert" : "status"}>{message.text}</div>}
        <section id="finding-overview" className="formSection">
          <div className="sectionTitle"><span>01</span><div><h2>범위와 분류</h2><p>Finding이 속한 자산과 보고서 공개 범위를 지정합니다.</p></div></div>
          <div className="fieldGrid">
            <label className="span2"><span>Finding 제목 <b>필수</b></span><input value={draft.title} onChange={(event) => patch({ title: event.target.value })} placeholder="예: Anonymous FTP access permits data exposure" /></label>
            <label><span>카테고리</span><input value={draft.category} onChange={(event) => patch({ category: event.target.value })} placeholder="Access Control" /></label>
            <label><span>상태</span><select value={draft.status} onChange={(event) => patch({ status: event.target.value })}>{statuses.map((value) => <option key={value}>{value}</option>)}</select></label>
            <fieldset className="assetSelector span2"><legend>영향받는 Target <small>{draft.target_ids.length}개 선택</small></legend>{targets.data?.map((target) => <label key={target.id}><input type="checkbox" checked={draft.target_ids.includes(target.id)} onChange={(event) => {
              const target_ids = event.target.checked ? [...draft.target_ids, target.id] : draft.target_ids.filter((id) => id !== target.id);
              const service_ids = event.target.checked ? draft.service_ids : draft.service_ids.filter((id) => !services.some((service) => service.target_id === target.id && service.id === id));
              patch({ target_ids, service_ids, target_id: target_ids[0] || null,
                service_id: service_ids[0] || null });
            }} /><span><strong>{target.ip}</strong><small>{target.name}</small></span></label>)}</fieldset>
            {draft.target_ids.length > 0 && <fieldset className="assetSelector span2"><legend>영향받는 Service <small>{draft.service_ids.length}개 선택</small></legend>{services.map((service) => <label key={service.id}><input type="checkbox" checked={draft.service_ids.includes(service.id)} onChange={(event) => {
              const service_ids = event.target.checked ? [...draft.service_ids, service.id] : draft.service_ids.filter((id) => id !== service.id);
              patch({ service_ids, service_id: service_ids[0] || null });
            }} /><span><strong>{service.port}/{service.protocol}</strong><small>{service.name}</small></span></label>)}</fieldset>}
            <label><span>보고서 공개 범위</span><select value={draft.disclosure} onChange={(event) => patch({ disclosure: event.target.value })}><option value="BOTH">Client + Internal</option><option value="CLIENT">Client only</option><option value="INTERNAL">Internal only</option></select></label>
            <label><span>수동 정렬 우선순위</span><input type="number" value={draft.sort_priority} onChange={(event) => patch({ sort_priority: +event.target.value })} /></label>
            <label className="span2"><span>태그 <small>쉼표로 구분</small></span><input value={draft.tags.join(", ")} onChange={(event) => patch({ tags: event.target.value.split(",").map((tag) => tag.trim()).filter(Boolean) })} placeholder="external, authentication, quick-win" /></label>
          </div>
        </section>
        <section id="finding-risk" className="formSection">
          <div className="sectionTitle"><span>02</span><div><h2>CVSS와 최종 위험도</h2><p>기술 점수와 사업 환경을 반영한 최종 위험도를 별도로 관리합니다.</p></div></div>
          <div className="metricGrid">{Object.entries(cvssMetrics).map(([key, metric]) => <label key={key}><span>{metric.label}<small>{key}</small></span><select value={parseVector(draft.cvss_vector)[key] || ""} onChange={(event) => setMetric(key, event.target.value)}><option value="">선택</option>{metric.values.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>)}</div>
          <div className="cvssPanel">
            <label><span>CVSS 3.1 Vector</span><div className="fieldAction"><input value={draft.cvss_vector} onChange={(event) => patch({ cvss_vector: event.target.value, cvss_score: undefined })} placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" /><Button onClick={checkCvss} disabled={cvssChecking}>{cvssChecking ? "계산 중" : "검증·계산"}</Button></div></label>
            <div className="scoreResult"><span>Base score</span><strong>{draft.cvss_score || "—"}</strong><Badge status={draft.severity || "unscored"}>{draft.severity || "벡터 미검증"}</Badge></div>
          </div>
          <div className="fieldGrid">
            <label><span>최종 위험도</span><select value={draft.final_risk} onChange={(event) => patch({ final_risk: event.target.value })}>{risks.map((risk) => <option key={risk}>{risk}</option>)}</select></label>
            <label className="span2"><span>위험도 조정 사유 {draft.severity && draft.severity !== draft.final_risk && <b>필수</b>}</span><textarea value={draft.risk_override_reason} onChange={(event) => patch({ risk_override_reason: event.target.value })} placeholder="예: 해당 서비스는 분리된 내부 관리망에서만 접근 가능" /></label>
          </div>
        </section>
        <section id="finding-details" className="formSection">
          <div className="sectionTitle"><span>03</span><div><h2>설명과 영향</h2><p>Client 독자와 기술 검토자가 같은 Finding을 각자의 관점에서 이해하도록 작성합니다.</p></div></div>
          <div className="writingGrid">
            <label><span>경영진 요약</span><textarea value={draft.summary} onChange={(event) => patch({ summary: event.target.value })} placeholder="무엇이 발견됐고 왜 중요한지 2–3문장으로 작성" /></label>
            <label><span>취약점 설명</span><textarea value={draft.description} onChange={(event) => patch({ description: event.target.value })} placeholder="조건, 원인, 관찰 결과를 사실 중심으로 작성" /></label>
            <label><span>비즈니스 영향 <small>Client report</small></span><textarea value={draft.business_impact} onChange={(event) => patch({ business_impact: event.target.value })} placeholder="업무 중단, 데이터 노출, 규제 영향" /></label>
            <label><span>기술적 영향 <small>Internal report</small></span><textarea value={draft.technical_impact} onChange={(event) => patch({ technical_impact: event.target.value })} placeholder="권한, 공격 표면, 후속 공격 가능성" /></label>
          </div>
        </section>
        <section id="finding-remediation" className="formSection">
          <div className="sectionTitle"><span>04</span><div><h2>재현과 개선</h2><p>검증 가능한 절차와 실행 가능한 개선안을 기록합니다.</p></div></div>
          <div className="writingGrid">
            <label><span>재현 절차</span><textarea className="codeField" value={draft.reproduction_steps} onChange={(event) => patch({ reproduction_steps: event.target.value })} placeholder={"1. 대상에 연결\n2. 명령 실행\n3. 결과 확인"} /></label>
            <label><span>권고사항</span><textarea value={draft.recommendation} onChange={(event) => patch({ recommendation: event.target.value })} placeholder="담당자가 바로 실행할 수 있도록 우선순위와 검증 방법을 포함" /></label>
            <label className="span2 internalField"><span>내부 작업자 메모 <Badge status="internal">Internal only</Badge></span><textarea value={draft.internal_notes} onChange={(event) => patch({ internal_notes: event.target.value })} placeholder="실패한 시도, 인증정보 위치, 재검증 준비사항" /></label>
          </div>
        </section>
        <section id="finding-retest" className="formSection">
          <div className="sectionTitle"><span>05</span><div><h2>재검증 이력</h2><p>기존 기록을 덮어쓰지 않고 개선 확인 결과를 시간순으로 누적합니다.</p></div></div>
          <div className="retestTimeline">
            {!draft.retests?.length && <EmptyState title="재검증 기록이 없습니다" description="개선 후 Evidence를 연결한 뒤 첫 재검증 결과를 남기세요." />}
            {draft.retests?.map((item) => <article key={item.id}>
              <header><Badge status={item.remediated ? "completed" : "pending"}>{item.result}</Badge><time>{new Date(item.tested_at).toLocaleString()}</time></header>
              <strong>{item.tester}</strong><p>{item.notes || "메모 없음"}</p>
              <small>개선 전 {item.before_evidence_ids.length}개 · 개선 후 {item.after_evidence_ids.length}개</small>
            </article>)}
          </div>
          <div className="retestForm">
            <label><span>담당자</span><input value={retest.tester} onChange={(event) => setRetest({ ...retest, tester: event.target.value })} placeholder="재검증 담당자" /></label>
            <label><span>결과</span><select value={retest.result} onChange={(event) => setRetest({ ...retest, result: event.target.value })}><option>Still Vulnerable</option><option>Partially Remediated</option><option>Remediated</option><option>Unable to Verify</option></select></label>
            <label className="retestCheck"><input type="checkbox" checked={retest.remediated} onChange={(event) => setRetest({ ...retest, remediated: event.target.checked, result: event.target.checked ? "Remediated" : retest.result })} /> Finding 상태를 Remediated로 변경</label>
            <label className="span2"><span>재검증 메모</span><textarea value={retest.notes} onChange={(event) => setRetest({ ...retest, notes: event.target.value })} placeholder="검증 방법, 관찰 결과, 남은 위험" /></label>
            <Button variant="primary" disabled={retestSaving || !selectedId} onClick={addRetest}>{retestSaving ? "기록 중…" : "재검증 기록 추가"}</Button>
          </div>
        </section>
      </div>
    </section>

    <aside className={`evidenceRail ${evidenceOpen ? "open" : ""}`} aria-label="연결 Evidence">
      <div className="panelHeading"><div><span>REPORT PROOF</span><h2>Evidence</h2></div><strong>{draft.evidence.length}</strong></div>
      <button className="closeEvidenceRail" aria-label="Evidence 패널 닫기" onClick={() => setEvidenceOpen(false)}>×</button>
      <p className="railHint">Client 공개 여부를 Evidence마다 검토하세요. 민감 Evidence는 기본적으로 Internal 전용입니다.</p>
      <div className="linkedEvidence">
        {!linkedEvidence.length && <EmptyState title="연결된 Evidence가 없습니다" description="아래 목록에서 재현 결과나 스크린샷을 연결하세요." />}
        {linkedEvidence.map(({ link, item }, index) => <article key={link.evidence_id}>
          <header><span>{index + 1}</span><div><strong>{item!.title}</strong><small>{item!.kind} · {item!.sensitivity}</small></div><button aria-label="연결 해제" onClick={() => removeLink(link.evidence_id)}>×</button></header>
          <input aria-label={`${item!.title} 캡션`} value={link.caption} onChange={(event) => updateLink(link.evidence_id, { caption: event.target.value })} placeholder="보고서 캡션" />
          <div className="evidenceControls">
            <label><input type="checkbox" checked={link.include_client} disabled={item!.sensitivity !== "normal"} onChange={(event) => updateLink(link.evidence_id, { include_client: event.target.checked })} /> Client</label>
            <label><input type="checkbox" checked={link.include_internal} onChange={(event) => updateLink(link.evidence_id, { include_internal: event.target.checked })} /> Internal</label>
            <label><input type="radio" name="primaryEvidence" checked={link.is_primary} onChange={() => patch({ evidence: draft.evidence.map((row) => ({ ...row, is_primary: row.evidence_id === link.evidence_id })) })} /> 대표</label>
            <select aria-label="Evidence 단계" value={link.phase} onChange={(event) => updateLink(link.evidence_id, { phase: event.target.value as Link["phase"] })}><option value="BEFORE">개선 전</option><option value="AFTER">개선 후</option></select>
          </div>
          <footer><button disabled={index === 0} onClick={() => moveLink(link.evidence_id, -1)}>↑ 위로</button><button disabled={index === linkedEvidence.length - 1} onClick={() => moveLink(link.evidence_id, 1)}>↓ 아래로</button></footer>
          {item!.kind === "screenshot" && <Button className="editImage" onClick={() => setEditingEvidence(item!)}>크롭·주석 편집</Button>}
        </article>)}
      </div>
      <details className="evidencePicker" open>
        <summary>Evidence 추가 <small>{visibleEvidence.length}</small></summary>
        {evidence.isLoading && <LoadingState label="Evidence 불러오는 중" />}
        {!evidence.isLoading && !visibleEvidence.length && <p>현재 범위에 추가할 Evidence가 없습니다.</p>}
        {visibleEvidence.map((item) => <button key={item.id} onClick={() => addEvidence(item)}><span>+</span><div><strong>{item.title}</strong><small>{item.kind} · {item.sensitivity}</small></div></button>)}
      </details>
      {selectedId && <Button variant="danger" className="deleteFinding" onClick={async () => {
        if (!confirm(`"${draft.title}" Finding을 삭제할까요? 이 작업은 되돌릴 수 없습니다.`)) return;
        await api(`/findings/${selectedId}`, { method: "DELETE" });
        const next = empty(); setSelectedId(undefined); setDraft(next); setBaseline(JSON.stringify(next));
        qc.invalidateQueries({ queryKey: ["findings"] }); qc.invalidateQueries({ queryKey: ["findingSummary"] });
      }}>Finding 삭제</Button>}
    </aside>
    {editingEvidence && <EvidenceImageEditor evidence={editingEvidence} onClose={() => setEditingEvidence(undefined)} />}
  </main>;
}
