import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, EmptyState, ErrorState, LoadingState } from "./ui";
import "./template-manager.css";

const severities = ["Critical", "High", "Medium", "Low", "Informational"];
const blank = () => ({ title: "", category: "", severity: "Informational",
  cvss_vector: "", description: "", impact: "", recommendation: "",
  references: [] as string[], cwe: "", cve: "", mitre_attack: [] as string[],
  tags: [] as string[] });
const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const response = await fetch("/api" + path, init);
  if (!response.ok) throw new Error((await response.json()).detail || response.statusText);
  return response.status === 204 ? undefined as T : response.json();
};

export default function FindingTemplateManager() {
  const qc = useQueryClient();
  const [selected, setSelected] = useState<number>();
  const [draft, setDraft] = useState<any>(blank());
  const [query, setQuery] = useState("");
  const [message, setMessage] = useState("");
  const [saving, setSaving] = useState(false);
  const templates = useQuery({ queryKey: ["templateManager", query],
    queryFn: () => api<any[]>(`/finding-templates?q=${encodeURIComponent(query)}`) });
  const patch = (values: any) => setDraft((current: any) => ({ ...current, ...values }));
  const select = (row: any) => {
    setSelected(row.id); setDraft({ ...row,
      references: JSON.parse(row.references || "[]"),
      mitre_attack: JSON.parse(row.mitre_attack || "[]"),
      tags: JSON.parse(row.tags || "[]"),
    }); setMessage("");
  };
  const save = async () => {
    if (!draft.title.trim()) { setMessage("템플릿 제목을 입력하세요."); return; }
    setSaving(true);
    try {
      const row = await api<any>(selected ? `/finding-templates/${selected}` : "/finding-templates", {
        method: selected ? "PUT" : "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(draft),
      });
      setSelected(row.id); select(row); setMessage("템플릿을 저장했습니다.");
      qc.invalidateQueries({ queryKey: ["templateManager"] });
      qc.invalidateQueries({ queryKey: ["findingTemplates"] });
    } catch (error) { setMessage(String(error)); }
    finally { setSaving(false); }
  };
  const importFile = async (file?: File) => {
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      if (!Array.isArray(parsed)) throw new Error("JSON 최상위 값은 배열이어야 합니다.");
      const result = await api<{ imported: number }>("/finding-templates/import?duplicate=skip", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(parsed),
      });
      setMessage(`${result.imported}개 템플릿을 가져왔습니다. 중복 제목은 건너뛰었습니다.`);
      qc.invalidateQueries({ queryKey: ["templateManager"] });
    } catch (error) { setMessage(`가져오기 실패: ${error}`); }
  };
  return <main className="templateManager">
    <aside>
      <div className="panelHeading"><div><span>REUSABLE CONTENT</span><h2>Finding library</h2></div><Button variant="primary" onClick={() => { setSelected(undefined); setDraft(blank()); setMessage(""); }}>새 템플릿</Button></div>
      <div className="templateTools"><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="제목 검색" />
        <a href="/api/finding-templates/export?format=json">JSON 내보내기</a>
        <a href="/api/finding-templates/export?format=yaml">YAML 내보내기</a>
        <label>JSON 가져오기<input type="file" accept="application/json,.json" onChange={(event) => importFile(event.target.files?.[0])} /></label>
      </div>
      {templates.isLoading && <LoadingState label="템플릿 불러오는 중" />}
      {templates.error && <ErrorState message={String(templates.error)} />}
      {!templates.isLoading && !templates.data?.length && <EmptyState title="저장된 템플릿이 없습니다" description="반복되는 Finding부터 라이브러리에 등록하세요." />}
      {templates.data?.map((row) => <button key={row.id} className={selected === row.id ? "active" : ""} onClick={() => select(row)}>
        <strong>{row.title}</strong><small>{row.category || "분류 없음"} · {row.severity}</small><em>{row.use_count}회</em>
      </button>)}
    </aside>
    <section>
      <header className="editorHeader"><div><span>{selected ? `TEMPLATE #${selected}` : "NEW TEMPLATE"}</span><h1>{draft.title || "새 Finding 템플릿"}</h1><p>적용 시점의 내용이 프로젝트 Finding에 스냅샷으로 저장됩니다.</p></div><div className="saveState"><Button variant="primary" disabled={saving} onClick={save}>{saving ? "저장 중…" : "템플릿 저장"}</Button></div></header>
      <div className="templateForm">
        {message && <div className="inlineNotice" role="status">{message}</div>}
        <div className="fieldGrid">
          <label className="span2"><span>제목</span><input value={draft.title} onChange={(event) => patch({ title: event.target.value })} /></label>
          <label><span>카테고리</span><input value={draft.category} onChange={(event) => patch({ category: event.target.value })} /></label>
          <label><span>기본 심각도</span><select value={draft.severity} onChange={(event) => patch({ severity: event.target.value })}>{severities.map((value) => <option key={value}>{value}</option>)}</select></label>
          <label className="span2"><span>기본 CVSS 3.1 Vector</span><input value={draft.cvss_vector} onChange={(event) => patch({ cvss_vector: event.target.value })} /></label>
          <label><span>CWE</span><input value={draft.cwe} onChange={(event) => patch({ cwe: event.target.value })} placeholder="CWE-287" /></label>
          <label><span>CVE</span><input value={draft.cve} onChange={(event) => patch({ cve: event.target.value })} placeholder="CVE-2026-…" /></label>
          {[["description", "설명"], ["impact", "영향"], ["recommendation", "권고사항"]].map(([key, label]) =>
            <label className="span2" key={key}><span>{label}</span><textarea value={draft[key]} onChange={(event) => patch({ [key]: event.target.value })} /></label>)}
          {[["references", "참고자료"], ["mitre_attack", "MITRE ATT&CK"], ["tags", "태그"]].map(([key, label]) =>
            <label className="span2" key={key}><span>{label} <small>쉼표로 구분</small></span><input value={draft[key].join(", ")} onChange={(event) => patch({ [key]: event.target.value.split(",").map((value) => value.trim()).filter(Boolean) })} /></label>)}
        </div>
        {selected && <div className="templateDanger"><Button onClick={async () => {
          const copy = await api<any>(`/finding-templates/${selected}/clone`, { method: "POST" }); select(copy); qc.invalidateQueries({ queryKey: ["templateManager"] });
        }}>복제</Button><Button variant="danger" onClick={async () => {
          if (!confirm(`"${draft.title}" 템플릿을 삭제할까요? 기존 Finding 스냅샷은 유지됩니다.`)) return;
          await api(`/finding-templates/${selected}`, { method: "DELETE" }); setSelected(undefined); setDraft(blank()); qc.invalidateQueries({ queryKey: ["templateManager"] });
        }}>삭제</Button></div>}
      </div>
    </section>
  </main>;
}
