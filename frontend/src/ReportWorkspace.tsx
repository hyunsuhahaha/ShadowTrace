import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import FindingWorkspace from "./FindingWorkspace";
import FindingTemplateManager from "./FindingTemplateManager";
import { EmptyState, ErrorState, LoadingState } from "./ui";
type Project = { id: number; name: string };
type Report = {
  id: number;
  project_id: number;
  title: string;
  template: string;
  markdown: string;
  evidence_links: string;
  exploit_research_links: string;
  sensitivity_reviewed: boolean;
};
type Evidence = {
  id: number;
  title: string;
  kind: string;
  sensitivity: string;
  include_report: boolean;
};
type Research = {
  id: number;
  title: string;
  target_address: string;
  port: number;
  validation_status: string;
};
const api = async <T,>(p: string, i?: RequestInit): Promise<T> => {
  const r = await fetch("/api" + p, i);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};
const blank = (projectId?: number): Partial<Report> => ({
  project_id: projectId,
  title: "OSCP Penetration Test Report",
  template: "oscp",
  markdown: "",
  evidence_links: "[]",
  exploit_research_links: "[]",
  sensitivity_reviewed: false,
});
export default function ReportWorkspace() {
  const qc = useQueryClient();
  const [projectId, setProjectId] = useState<number | undefined>(
      () => Number(localStorage.getItem("oscp-workspace-project")) || undefined),
    [reportId, setReportId] = useState<number>(),
    [draft, setDraft] = useState<Partial<Report>>(blank()),
    [baseline, setBaseline] = useState(JSON.stringify(blank())),
    [preview, setPreview] = useState(""),
    [view, setView] = useState<"findings" | "library" | "reports">("findings"),
    [profile, setProfile] = useState<"client" | "internal">("client"),
    [error, setError] = useState("");
  const projects = useQuery({
      queryKey: ["projects"],
      queryFn: () => api<Project[]>("/projects"),
    }),
    reports = useQuery({
      queryKey: ["reports", projectId],
      queryFn: () => api<Report[]>(`/reports?project_id=${projectId}`),
      enabled: !!projectId,
    }),
    evidence = useQuery({
      queryKey: ["projectEvidence", projectId],
      queryFn: () => api<Evidence[]>(`/evidence?project_id=${projectId}`),
      enabled: !!projectId,
    }),
    research = useQuery({
      queryKey: ["reportResearch", projectId],
      queryFn: () =>
        api<Research[]>(`/projects/${projectId}/exploit-research?limit=500`),
      enabled: !!projectId,
    });
  useEffect(() => {
    if (!projectId && projects.data?.[0]) setProjectId(projects.data[0].id);
  }, [projects.data, projectId]);
  useEffect(() => {
    setReportId(undefined);
    setDraft(blank(projectId));
    setBaseline(JSON.stringify(blank(projectId)));
  }, [projectId]);
  const dirty = JSON.stringify(draft) !== baseline;
  const links = (): any[] => JSON.parse(draft.evidence_links || "[]");
  const toggle = (item: Evidence) => {
    const current = links(),
      exists = current.some((x) => x.id === item.id);
    setDraft({
      ...draft,
      evidence_links: JSON.stringify(
        exists
          ? current.filter((x) => x.id !== item.id)
          : [...current, { id: item.id, caption: item.title }],
      ),
    });
  };
  const researchLinks = (): number[] => {
    try {
      return JSON.parse(draft.exploit_research_links || "[]");
    } catch {
      return [];
    }
  };
  const toggleResearch = (item: Research) => {
    const current = researchLinks();
    setDraft({
      ...draft,
      exploit_research_links: JSON.stringify(
        current.includes(item.id)
          ? current.filter((id) => id !== item.id)
          : [...current, item.id],
      ),
    });
  };
  const payload = () => ({
    ...draft,
    project_id: projectId,
    evidence_links: links(),
    exploit_research_links: researchLinks(),
  });
  const save = async () => {
    try {
      setError("");
      const row = await api<Report>(
        reportId ? `/reports/${reportId}` : "/reports",
        {
          method: reportId ? "PUT" : "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload()),
        },
      );
      setReportId(row.id);
      setDraft(row);
      setBaseline(JSON.stringify(row));
      qc.invalidateQueries({ queryKey: ["reports", projectId] });
    } catch (e) {
      setError(String(e));
    }
  };
  const showPreview = async () => {
    if (!reportId) {
      setError("미리 보기 전에 보고서를 저장하세요.");
      return;
    }
    const r = await fetch(`/api/reports/${reportId}/export?format=html&profile=${profile}`);
    if (!r.ok) {
      setError((await r.json()).detail);
      return;
    }
    setPreview(await r.text());
  };
  const select = (r: Report) => {
    if (dirty && !confirm("저장하지 않은 변경사항을 버리고 다른 보고서를 열까요?")) return;
    setReportId(r.id);
    setDraft(r);
    setBaseline(JSON.stringify(r));
    setPreview("");
  };
  return (
    <div className="reportPage">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>보고서</small>
          </div>
        </div>
      </header>
      <nav>
        <span className="reportProject">{projects.data?.find((p) => p.id === projectId)?.name || "프로젝트 선택 대기 중"}</span>
        <button
          className={view === "reports" ? "active" : ""}
          onClick={() => {
            if (dirty && !confirm("저장하지 않은 변경사항을 버리고 새 보고서를 만들까요?")) return;
            setView("reports");
            setReportId(undefined);
            setDraft(blank(projectId));
            setBaseline(JSON.stringify(blank(projectId)));
          }}
        >
          새 보고서
        </button>
        <button className={view === "findings" ? "active" : ""} onClick={() => setView("findings")}>Findings</button>
        <button className={view === "library" ? "active" : ""} onClick={() => setView("library")}>Finding 라이브러리</button>
        <button className={view === "reports" ? "active" : ""} onClick={() => setView("reports")}>보고서 생성</button>
      </nav>
      {view === "findings" ? <FindingWorkspace projectId={projectId} /> :
      view === "library" ? <FindingTemplateManager /> :
      <main className="reportLayout">
        <aside>
          <h3>보고서</h3>
          {reports.isLoading && <LoadingState label="보고서 목록을 불러오는 중" />}
          {reports.error && <ErrorState message={String(reports.error)} />}
          {!reports.isLoading && !reports.data?.length &&
            <EmptyState title="저장된 보고서가 없습니다" description="새 보고서를 저장하세요." />}
          {reports.data?.map((r) => (
            <button
              className={r.id === reportId ? "active" : ""}
              key={r.id}
              onClick={() => select(r)}
            >
              <b>{r.title}</b>
              <small>{r.template}</small>
            </button>
          ))}
          <h3>증적 목록</h3>
          {evidence.isLoading && <LoadingState label="증적 목록을 불러오는 중" />}
          {evidence.error && <ErrorState message={String(evidence.error)} />}
          {!evidence.isLoading && !evidence.data?.length &&
            <small>연결할 Evidence가 없습니다.</small>}
          {evidence.data?.map((x) => (
            <label key={x.id}>
              <input
                type="checkbox"
                checked={links().some((link) => link.id === x.id)}
                onChange={() => toggle(x)}
              />
              <span>
                {x.title}
                <small>
                  {x.kind} · {x.sensitivity}
                </small>
              </span>
            </label>
          ))}
          <h3>Exploit Research</h3>
          {research.isLoading && <LoadingState label="조사 후보를 불러오는 중" />}
          {research.error && <ErrorState message={String(research.error)} />}
          {!research.isLoading && !research.data?.length && (
            <small>연결할 조사 후보가 없습니다.</small>
          )}
          {research.data?.map((item) => (
            <label key={item.id}>
              <input
                type="checkbox"
                checked={researchLinks().includes(item.id)}
                onChange={() => toggleResearch(item)}
              />
              <span>
                {item.title}
                <small>
                  {item.target_address}:{item.port} · {item.validation_status}
                </small>
              </span>
            </label>
          ))}
        </aside>
        <section>
          <div className="reportTools">
            <input
              value={draft.title || ""}
              onChange={(e) => setDraft({ ...draft, title: e.target.value })}
            />
            <button onClick={save}>저장</button>
            <span className={dirty ? "reportDirty" : "reportSaved"}>
              {dirty ? "저장되지 않은 변경" : "저장됨"}
            </span>
            <select aria-label="미리보기 프로파일" value={profile} onChange={(e) => { setProfile(e.target.value as "client" | "internal"); setPreview(""); }}>
              <option value="client">Client profile</option><option value="internal">Internal profile</option>
            </select>
            <button onClick={showPreview}>미리 보기</button>
            {reportId && (
              <>
                <a href={`/api/reports/${reportId}/export?format=markdown&profile=client`}>Markdown</a>
                <a href={`/api/reports/${reportId}/export?format=html&profile=client`}>Client HTML</a>
                <a href={`/api/reports/${reportId}/export?format=pdf&profile=client`}>Client PDF</a>
                <a href={`/api/reports/${reportId}/export?format=docx&profile=client`}>Client Word</a>
                <a href={`/api/reports/${reportId}/export?format=pdf&profile=internal`}>Internal PDF</a>
                <a href={`/api/reports/${reportId}/export?format=docx&profile=internal`}>Internal Word</a>
              </>
            )}
          </div>
          <label className="sensitiveReview">
            <input
              type="checkbox"
              checked={draft.sensitivity_reviewed}
              onChange={(e) =>
                setDraft({ ...draft, sensitivity_reviewed: e.target.checked })
              }
            />{" "}
            이 보고서에 포함된 민감정보를 검토했습니다.
          </label>
          {error && <p className="webError">{error}</p>}
          <div className="reportEditor">
            <textarea
              value={draft.markdown || ""}
              onChange={(e) => setDraft({ ...draft, markdown: e.target.value })}
              placeholder="Markdown으로 보고서를 작성하세요. 새 보고서를 저장하면 OSCP 구조가 삽입됩니다."
            />
            <iframe title="보고서 미리 보기" srcDoc={preview} />
          </div>
        </section>
      </main>
      }
    </div>
  );
}
