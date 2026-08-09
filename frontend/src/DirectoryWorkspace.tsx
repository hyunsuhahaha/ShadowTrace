import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { EmptyState, ErrorState, LoadingState } from "./ui";
type Project = { id: number; name: string };
type Obj = {
  id: number;
  project_id: number;
  kind: string;
  name: string;
  domain: string;
  attributes: string;
  notes: string;
  tags: string;
  source: string;
};
type Rel = {
  id: number;
  source_id: number;
  target_id: number;
  relation: string;
  notes: string;
};
const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const r = await fetch("/api" + path, init);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};
export default function DirectoryWorkspace() {
  const qc = useQueryClient();
  const [projectId, setProjectId] = useState<number>(),
    [query, setQuery] = useState(""),
    [kind, setKind] = useState(""),
    [draft, setDraft] = useState({
      kind: "user",
      name: "",
      domain: "",
      attributes: "{}",
      notes: "",
      tags: "[]",
    }),
    [relation, setRelation] = useState({
      source_id: 0,
      target_id: 0,
      relation: "observed_member_of",
    }),
    [error, setError] = useState("");
  const projects = useQuery({
      queryKey: ["projects"],
      queryFn: () => api<Project[]>("/projects"),
    }),
    objects = useQuery({
      queryKey: ["directoryObjects", projectId, query, kind],
      queryFn: () =>
        api<Obj[]>(
          `/directory/objects?project_id=${projectId}&query=${encodeURIComponent(query)}&kind=${kind}`,
        ),
      enabled: !!projectId,
    }),
    relations = useQuery({
      queryKey: ["directoryRelations", projectId],
      queryFn: () => api<Rel[]>(`/directory/relations?project_id=${projectId}`),
      enabled: !!projectId,
    });
  useEffect(() => {
    if (!projectId && projects.data?.[0]) setProjectId(projects.data[0].id);
  }, [projects.data, projectId]);
  const names = useMemo(
    () => new Map(objects.data?.map((x) => [x.id, x.name])),
    [objects.data],
  );
  const create = async () => {
    if (!projectId) return;
    try {
      await api("/directory/objects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_id: projectId,
          target_id: null,
          kind: draft.kind,
          name: draft.name,
          domain: draft.domain,
          attributes: JSON.parse(draft.attributes),
          notes: draft.notes,
          tags: JSON.parse(draft.tags),
          source: "manual",
        }),
      });
      setDraft({ ...draft, name: "" });
      qc.invalidateQueries({ queryKey: ["directoryObjects"] });
    } catch (e) {
      setError(String(e));
    }
  };
  const importFile = async (file: File) => {
    if (!projectId) return;
    const d = new FormData();
    d.append("file", file);
    const r = await fetch(
      `/api/directory/objects/import?project_id=${projectId}`,
      { method: "POST", body: d },
    );
    if (!r.ok) {
      setError((await r.json()).detail);
      return;
    }
    qc.invalidateQueries({ queryKey: ["directoryObjects"] });
  };
  const link = async () => {
    if (!projectId || !relation.source_id || !relation.target_id) return;
    try {
      await api("/directory/relations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...relation,
          project_id: projectId,
          evidence_id: null,
          notes: "",
        }),
      });
      qc.invalidateQueries({ queryKey: ["directoryRelations"] });
    } catch (e) {
      setError(String(e));
    }
  };
  return (
    <div className="directoryPage">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>AD 정보</small>
          </div>
        </div>
        <a href="#scans">← Scan Center</a>
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
        <input
          placeholder="관찰된 객체 검색"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">모든 종류</option>
          {[
            "domain",
            "user",
            "group",
            "computer",
            "share",
            "spn",
            "session",
            "trust",
            "credential_source",
          ].map((x) => (
            <option key={x}>{x}</option>
          ))}
        </select>
        <label>
          CSV/JSON 가져오기
          <input
            type="file"
            accept=".csv,.json"
            onChange={(e) =>
              e.target.files?.[0] && importFile(e.target.files[0])
            }
          />
        </label>
      </nav>
      <main className="directoryLayout">
        <aside>
          <h3>관찰 항목 추가</h3>
          <select
            value={draft.kind}
            onChange={(e) => setDraft({ ...draft, kind: e.target.value })}
          >
            {[
              "domain",
              "user",
              "group",
              "computer",
              "share",
              "spn",
              "session",
              "trust",
              "credential_source",
            ].map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
          <input
            placeholder="이름"
            value={draft.name}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })}
          />
          <input
            placeholder="Domain"
            value={draft.domain}
            onChange={(e) => setDraft({ ...draft, domain: e.target.value })}
          />
          <textarea
            placeholder="속성 JSON"
            value={draft.attributes}
            onChange={(e) => setDraft({ ...draft, attributes: e.target.value })}
          />
          <textarea
            placeholder="메모"
            value={draft.notes}
            onChange={(e) => setDraft({ ...draft, notes: e.target.value })}
          />
          <button onClick={create}>관찰 객체 추가</button>
          {error && <p className="webError">{error}</p>}
        </aside>
        <section>
          <div className="directoryObjects">
            {objects.isLoading && <LoadingState label="관찰 객체를 불러오는 중" />}
            {objects.error && <ErrorState message={String(objects.error)} />}
            {!objects.isLoading && !objects.data?.length &&
              <EmptyState title="관찰 객체가 없습니다" description="왼쪽에서 새 관찰 객체를 추가하세요." />}
            {objects.data?.map((o) => (
              <article key={o.id}>
                <span>{o.kind}</span>
                <b>{o.name}</b>
                <small>
                  {o.domain || "—"} · {o.source}
                </small>
                <code>{o.attributes}</code>
              </article>
            ))}
          </div>
          <div className="relationComposer">
            <select
              value={relation.source_id}
              onChange={(e) =>
                setRelation({ ...relation, source_id: +e.target.value })
              }
            >
              <option value="0">출발 객체</option>
              {objects.data?.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
            <input
              value={relation.relation}
              onChange={(e) =>
                setRelation({ ...relation, relation: e.target.value })
              }
            />
            <select
              value={relation.target_id}
              onChange={(e) =>
                setRelation({ ...relation, target_id: +e.target.value })
              }
            >
              <option value="0">도착 객체</option>
              {objects.data?.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name}
                </option>
              ))}
            </select>
            <button onClick={link}>관계 기록</button>
          </div>
          <div className="observedGraph">
            {relations.isLoading && <LoadingState label="관계를 불러오는 중" />}
            {relations.error && <ErrorState message={String(relations.error)} />}
            {!relations.isLoading && !relations.data?.length &&
              <EmptyState title="기록된 관계가 없습니다" description="위에서 출발·도착 객체를 선택하고 관계를 기록하세요." />}
            {relations.data?.map((r) => (
              <div key={r.id}>
                <b>{names.get(r.source_id) || `#${r.source_id}`}</b>
                <span>— {r.relation} →</span>
                <b>{names.get(r.target_id) || `#${r.target_id}`}</b>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
