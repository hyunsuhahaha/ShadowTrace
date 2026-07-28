import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
type Project = { id: number; name: string };
type Report = {
  id: number;
  project_id: number;
  title: string;
  template: string;
  markdown: string;
  evidence_links: string;
  sensitivity_reviewed: boolean;
};
type Evidence = {
  id: number;
  title: string;
  kind: string;
  sensitivity: string;
  include_report: boolean;
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
  sensitivity_reviewed: false,
});
export default function ReportWorkspace() {
  const qc = useQueryClient();
  const [projectId, setProjectId] = useState<number>(),
    [reportId, setReportId] = useState<number>(),
    [draft, setDraft] = useState<Partial<Report>>(blank()),
    [preview, setPreview] = useState(""),
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
    });
  useEffect(() => {
    if (!projectId && projects.data?.[0]) setProjectId(projects.data[0].id);
  }, [projects.data, projectId]);
  useEffect(() => {
    setReportId(undefined);
    setDraft(blank(projectId));
  }, [projectId]);
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
  const payload = () => ({
    ...draft,
    project_id: projectId,
    evidence_links: links(),
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
      qc.invalidateQueries({ queryKey: ["reports", projectId] });
    } catch (e) {
      setError(String(e));
    }
  };
  const showPreview = async () => {
    if (!reportId) {
      setError("Save the report before previewing.");
      return;
    }
    const r = await fetch(`/api/reports/${reportId}/export?format=html`);
    if (!r.ok) {
      setError((await r.json()).detail);
      return;
    }
    setPreview(await r.text());
  };
  const select = (r: Report) => {
    setReportId(r.id);
    setDraft(r);
    setPreview("");
  };
  return (
    <div className="reportPage">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>Reports</small>
          </div>
        </div>
        <a href="#">← Scan Center</a>
      </header>
      <nav>
        <select
          value={projectId || ""}
          onChange={(e) => setProjectId(+e.target.value)}
        >
          {projects.data?.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <button
          onClick={() => {
            setReportId(undefined);
            setDraft(blank(projectId));
          }}
        >
          New report
        </button>
        <span>
          STRUCTURE AND EXPORT ONLY · ALL FINDINGS, IMPACT, AND JUDGMENT ARE
          USER-AUTHORED
        </span>
      </nav>
      <main className="reportLayout">
        <aside>
          <h3>REPORTS</h3>
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
          <h3>EVIDENCE INDEX</h3>
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
        </aside>
        <section>
          <div className="reportTools">
            <input
              value={draft.title || ""}
              onChange={(e) => setDraft({ ...draft, title: e.target.value })}
            />
            <button onClick={save}>Save</button>
            <button onClick={showPreview}>Preview</button>
            {reportId && (
              <>
                <a href={`/api/reports/${reportId}/export?format=html`}>HTML</a>
                <a href={`/api/reports/${reportId}/export?format=pdf`}>PDF</a>
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
            I reviewed sensitive information included in this report.
          </label>
          {error && <p className="webError">{error}</p>}
          <div className="reportEditor">
            <textarea
              value={draft.markdown || ""}
              onChange={(e) => setDraft({ ...draft, markdown: e.target.value })}
              placeholder="Write the report in Markdown. The OSCP structure is inserted when a new report is saved."
            />
            <iframe title="Report preview" srcDoc={preview} />
          </div>
        </section>
      </main>
    </div>
  );
}
