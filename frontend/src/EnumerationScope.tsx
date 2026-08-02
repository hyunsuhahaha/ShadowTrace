import VpnControl from "./VpnControl";
import type {Project, Target} from "./enumerationModel";

type MissingTool = {name: string; install: string};

type Props = {
  project?: Project;
  target?: Target;
  projects?: Project[];
  targets?: Target[];
  projectId?: number;
  targetId?: number;
  toolsLoading: boolean;
  missingTools: MissingTool[];
  onCreateProject: () => void;
  onSelectProject: (id: number) => void;
  onCreateTarget: () => void;
  onSelectTarget: (id: number) => void;
  onUpload: (file: File) => void;
};

export default function EnumerationScope({
  project,
  target,
  projects,
  targets,
  projectId,
  targetId,
  toolsLoading,
  missingTools,
  onCreateProject,
  onSelectProject,
  onCreateTarget,
  onSelectTarget,
  onUpload,
}: Props) {
  return <>
    <header>
      <div className="brand">
        <span className="mark">OW</span>
        <div>
          <b>OSCP Workspace</b>
          <small>로컬 Enumeration 작업 공간</small>
        </div>
      </div>
      <div className="target">
        <span>프로젝트</span>
        <b>{project?.name || "프로젝트 없음"}</b>
        <i>/</i>
        <span>대상</span>
        <b>{target?.ip || "—"}</b>
      </div>
      <VpnControl />
    </header>
    <nav>
      <button onClick={onCreateProject}>＋ 프로젝트</button>
      <select
        aria-label="프로젝트 선택"
        value={projectId || ""}
        onChange={(event) => onSelectProject(Number(event.target.value))}
      >
        <option value="">프로젝트 선택</option>
        {projects?.map((item) => (
          <option key={item.id} value={item.id}>{item.name}</option>
        ))}
      </select>
      <button disabled={!projectId} onClick={onCreateTarget}>＋ 대상</button>
      <select
        aria-label="대상 선택"
        value={targetId || ""}
        onChange={(event) => onSelectTarget(Number(event.target.value))}
      >
        <option value="">대상 선택</option>
        {targets?.map((item) => (
          <option key={item.id} value={item.id}>{item.name} · {item.ip}</option>
        ))}
      </select>
      <label className="upload">
        Nmap XML 가져오기
        <input
          type="file"
          accept=".xml"
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) onUpload(file);
          }}
        />
      </label>
      <span
        className="tools"
        title={missingTools.map((item) => item.install).join("\n")}
      >
        {toolsLoading
          ? "도구 상태 확인 중"
          : missingTools.length
            ? `미설치: ${missingTools.map((item) => item.name).join(", ")}`
            : "필수 도구 설치됨"}
      </span>
    </nav>
  </>;
}
