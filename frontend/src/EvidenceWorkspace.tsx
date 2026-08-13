import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { EmptyState, ErrorState, LoadingState } from "./ui";
type Target = { id: number; project_id: number; name: string; ip: string };
type Evidence = {
  id: number;
  title: string;
  description: string;
  kind: string;
  source_type: string;
  source_id?: number;
  original_name: string;
  sha256: string;
  size: number;
  username: string;
  hostname: string;
  privilege: string;
  sensitivity: string;
  include_report: boolean;
  tags: string;
  markdown: string;
  duplicate_of?: number;
  acquired_at: string;
};
type Preview = { content: string; truncated: boolean; language: string };
export const formatEvidenceSize = (size: number) => size < 1024 ? `${size} B`
  : size < 1024 * 1024 ? `${(size / 1024).toFixed(size < 10 * 1024 ? 1 : 0)} KiB`
  : `${(size / 1024 / 1024).toFixed(1)} MiB`;
const sourceLabel = (item: Evidence) => {
  const source = item.source_type === "scan" ? "Scan"
    : item.source_type === "hash_crack" || item.source_type === "hash_crack_job" ? "Hash cracking"
    : item.source_type === "execution" ? "Execution"
    : item.source_type === "upload" ? "직접 업로드" : item.source_type || "기록";
  return `${source}${item.source_id ? ` #${item.source_id}` : ""}`;
};
const KINDS = [
  { id: "auto", label: "자동 감지" },
  { id: "screenshot", label: "스크린샷" },
  { id: "flag", label: "Flag (user.txt / root.txt)" },
  { id: "command_output", label: "명령어 출력" },
  { id: "http", label: "HTTP" },
  { id: "nmap", label: "Nmap" },
  { id: "attachment", label: "첨부파일" },
  { id: "markdown", label: "마크다운" },
];
const KIND_LABEL: Record<string, string> = Object.fromEntries(
  KINDS.map((kind) => [kind.id, kind.label]));
type Research = { id: number; title: string; target_id: number };
const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const r = await fetch("/api" + path, init);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};
export default function EvidenceWorkspace() {
  const qc = useQueryClient();
  const [targetId, setTargetId] = useState<number>(),
    [researchId, setResearchId] = useState<number>(),
    [selected, setSelected] = useState<number[]>([]),
    [active, setActive] = useState<Evidence>(),
    [uploadKind, setUploadKind] = useState("auto"),
    [error, setError] = useState("");
  const targets = useQuery({
    queryKey: ["allTargets"],
    queryFn: () => api<Target[]>("/targets"),
  });
  const target = targets.data?.find((x) => x.id === targetId);
  const evidence = useQuery({
    queryKey: ["evidence", targetId],
    queryFn: () => api<Evidence[]>(`/evidence?target_id=${targetId}`),
    enabled: !!targetId,
  });
  const preview = useQuery({
    queryKey: ["evidencePreview", active?.id],
    queryFn: () => api<Preview>(`/evidence/${active!.id}/preview`),
    enabled: !!active && active.kind !== "screenshot",
    retry: false,
  });
  const research = useQuery({
    queryKey: ["evidenceResearch", target?.project_id, targetId],
    queryFn: () => api<Research[]>(
      `/projects/${target?.project_id}/exploit-research?target_id=${targetId}`),
    enabled: !!target,
  });
  useEffect(() => {
    if (!targetId && targets.data?.[0]) setTargetId(targets.data[0].id);
  }, [targets.data, targetId]);
  useEffect(() => {
    if (targetId) dispatchEvent(new CustomEvent("oscp-target-change", {detail: targetId}));
  }, [targetId]);
  const upload = async (file: File) => {
    if (!target) return;
    const data = new FormData();
    data.append("project_id", String(target.project_id));
    data.append("target_id", String(target.id));
    if (researchId) data.append("exploit_research_id", String(researchId));
    data.append("title", file.name);
    data.append(
      "kind",
      uploadKind !== "auto"
        ? uploadKind
        : file.type.startsWith("image/") ? "screenshot" : "attachment",
    );
    data.append("file", file);
    const r = await fetch("/api/evidence/upload", {
      method: "POST",
      body: data,
    });
    if (!r.ok) {
      setError((await r.json()).detail);
      return;
    }
    await qc.invalidateQueries({ queryKey: ["evidence", targetId] });
  };
  const save = async () => {
    if (!active) return;
    const body = {
      title: active.title,
      description: active.description,
      service_id: null,
      username: active.username,
      hostname: active.hostname,
      privilege: active.privilege,
      sensitivity: active.sensitivity,
      include_report: active.include_report,
      tags: JSON.parse(active.tags || "[]"),
      markdown: active.markdown,
    };
    const updated = await api<Evidence>(`/evidence/${active.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    setActive(updated);
    qc.invalidateQueries({ queryKey: ["evidence", targetId] });
  };
  const exportZip = async () => {
    const r = await fetch("/api/evidence/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(selected),
    });
    if (!r.ok) {
      setError((await r.json()).detail);
      return;
    }
    const blob = await r.blob(),
      url = URL.createObjectURL(blob),
      a = document.createElement("a");
    a.href = url;
    a.download = "evidence-export.zip";
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="evidencePage">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>증적</small>
          </div>
        </div>
        <a href="#scans">← Scan Center</a>
      </header>
      <nav>
        <select
          aria-label="대상 선택"
          value={targetId || ""}
          onChange={(e) => setTargetId(+e.target.value)}
        >
          {targets.data?.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} · {t.ip}
            </option>
          ))}
        </select>
        <button disabled={!selected.length} onClick={exportZip}
          title={selected.length ? undefined : "먼저 목록에서 항목을 선택하세요"}>
          선택 항목 ZIP 내보내기
        </button>
        <select aria-label="Exploit Research 연결" value={researchId || ""}
          onChange={(e) => setResearchId(
            e.target.value ? +e.target.value : undefined)}>
          <option value="">Exploit Research 연결 안 함</option>
          {research.data?.map((item) =>
            <option key={item.id} value={item.id}>{item.title}</option>)}
        </select>
      </nav>
      <main className="evidenceLayout">
        <section className="evidenceList">
          <label>
            업로드 분류
            <select value={uploadKind} onChange={(e) => setUploadKind(e.target.value)}>
              {KINDS.map((k) => <option key={k.id} value={k.id}>{k.label}</option>)}
            </select>
          </label>
          <label
            className="dropZone"
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              Array.from(e.dataTransfer.files).forEach(upload);
            }}
          >
            증적 파일을 여기에 놓으세요
            <input
              type="file"
              multiple
              onChange={(e) => Array.from(e.target.files || []).forEach(upload)}
            />
          </label>
          {error && <p className="webError">{error}</p>}
          {evidence.isLoading && <LoadingState label="Evidence를 불러오는 중" />}
          {evidence.error && <ErrorState message={String(evidence.error)} />}
          {!evidence.isLoading && !evidence.data?.length &&
            <EmptyState title="저장된 Evidence가 없습니다" description="파일을 드래그하거나 위에서 업로드하세요." />}
          {evidence.data?.map((item) => (
            <article
              key={item.id}
              className={active?.id === item.id ? "active" : ""}
            >
              <input
                type="checkbox"
                checked={selected.includes(item.id)}
                onChange={(e) =>
                  setSelected((ids) =>
                    e.target.checked
                      ? [...ids, item.id]
                      : ids.filter((id) => id !== item.id),
                  )
                }
              />
              <button onClick={() => setActive(item)}>
                <span className="evidenceItemHead"><b>{item.title}</b>
                  <em>{KIND_LABEL[item.kind] || item.kind}</em></span>
                <span>{sourceLabel(item)} · {formatEvidenceSize(item.size)} · {new Date(item.acquired_at).toLocaleString()}</span>
                <small>{item.original_name || "파일 없는 메모"}</small>
                {item.description && <p>{item.description}</p>}
                {item.duplicate_of && (
                  <em>#{item.duplicate_of}의 중복 파일</em>
                )}
              </button>
            </article>
          ))}
        </section>
        <section className="evidencePreview">
          {active ? (
            <>
              <header className="evidencePreviewHead">
                <div><span>{KIND_LABEL[active.kind] || active.kind} · {sourceLabel(active)}</span>
                  <h2>{active.title}</h2>
                  <p>{active.original_name || "Markdown note"} · {formatEvidenceSize(active.size)} · {new Date(active.acquired_at).toLocaleString()}</p>
                </div>
                {active.original_name && <a href={`/api/evidence/${active.id}/file`}>다운로드</a>}
              </header>
              <div className="previewFile">
                {active.kind === "screenshot" ? (
                  <img src={`/api/evidence/${active.id}/file`} alt={active.title} />
                ) : preview.isLoading ? (
                  <LoadingState label="내용 미리보기 불러오는 중" />
                ) : preview.data ? (
                  <><pre data-language={preview.data.language}>{preview.data.content}</pre>
                    {preview.data.truncated && <small>앞 256 KiB만 표시합니다.</small>}</>
                ) : (
                  <div className="previewUnavailable"><b>브라우저 미리보기를 지원하지 않는 파일입니다.</b>
                    <span>원본 파일을 다운로드해 확인하세요.</span></div>
                )}
              </div>
              <div className="evidenceFacts">
                <span><small>출처</small><b>{sourceLabel(active)}</b></span>
                <span><small>SHA-256</small><code title={active.sha256}>{active.sha256.slice(0, 16)}…</code></span>
                <span><small>민감도</small><b>{active.sensitivity}</b></span>
                <span><small>보고서</small><b>{active.include_report ? "포함" : "제외"}</b></span>
              </div>
              <h3 className="evidenceMetaTitle">분류 및 메타데이터</h3>
              <label>
                제목
                <input
                  value={active.title}
                  onChange={(e) =>
                    setActive({ ...active, title: e.target.value })
                  }
                />
              </label>
              <label>
                설명
                <textarea
                  value={active.description}
                  onChange={(e) =>
                    setActive({ ...active, description: e.target.value })
                  }
                />
              </label>
              <label>
                획득한 사용자명
                <input
                  value={active.username}
                  placeholder="예: postgres"
                  onChange={(e) =>
                    setActive({ ...active, username: e.target.value })
                  }
                />
              </label>
              <label>
                호스트명
                <input
                  value={active.hostname}
                  onChange={(e) =>
                    setActive({ ...active, hostname: e.target.value })
                  }
                />
              </label>
              <label>
                권한 레벨
                <input
                  value={active.privilege}
                  placeholder="예: low-priv, root, Administrator"
                  onChange={(e) =>
                    setActive({ ...active, privilege: e.target.value })
                  }
                />
              </label>
              <label>
                민감도
                <select
                  value={active.sensitivity}
                  onChange={(e) =>
                    setActive({ ...active, sensitivity: e.target.value })
                  }
                >
                  <option>normal</option>
                  <option>sensitive</option>
                  <option>secret</option>
                </select>
              </label>
              <label>
                <input
                  type="checkbox"
                  checked={active.include_report}
                  onChange={(e) =>
                    setActive({ ...active, include_report: e.target.checked })
                  }
                />{" "}
                보고서에 포함
              </label>
              <label>
                태그 JSON
                <input
                  value={active.tags}
                  onChange={(e) =>
                    setActive({ ...active, tags: e.target.value })
                  }
                />
              </label>
              <button onClick={save}>증적 메타데이터 저장</button>
            </>
          ) : (
            <div className="empty">
              미리 보고 분류할 증적을 선택하세요.
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
