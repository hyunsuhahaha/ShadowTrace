import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  useEffect, useRef, useState,
  type CSSProperties, type PointerEvent as ReactPointerEvent, type ReactNode,
} from "react";
import { Badge, Button, ErrorState, LoadingState } from "./ui";
import VpnControl from "./VpnControl";
import MetasploitLock from "./MetasploitLock";
import CommandPalette from "./CommandPalette";
import "./layout-controls.css";

type Project = { id: number; name: string; metasploit_target_id?: number | null };
type Target = { id: number; project_id: number; name: string; ip: string };
type Service = {
  id: number; target_id: number; port: number; protocol: string;
  name: string; product: string; scripts: string;
};

const sidebarMin = 184;
const sidebarMax = 420;
const sidebarCollapsedWidth = 58;
const clampSidebar = (width: number) => Math.min(sidebarMax, Math.max(sidebarMin, width));

const pages = [
  {
    label: "Discover",
    items: [
      { route: "scans", step: "01", label: "Scan Center", detail: "대상 등록과 서비스 발견" },
      { route: "enumeration", step: "02", label: "Service Enumeration", detail: "서비스 조사와 명령 실행" },
      { route: "web", step: "03", label: "Web Testing · Intruder", detail: "HTTP 요청 변형과 응답 비교" },
      { route: "exploit-research", step: "04", label: "Exploit Research", detail: "후보와 PoC 기록" },
      { route: "runbooks", step: "", label: "Runbooks", detail: "방법론과 수행 진행률" },
      { route: "post-exploitation", step: "", label: "Post-Exploitation", detail: "자격 증명 헌팅" },
      { route: "hash-cracking", step: "", label: "Hash Cracking", detail: "탈취한 해시 크래킹" },
      { route: "tools", step: "", label: "Tools", detail: "미탐지·오분류 서비스의 전체 명령 탐색" },
    ],
  },
  {
    label: "Document",
    items: [
      { route: "evidence", step: "05", label: "Evidence", detail: "증거 저장과 분류" },
      { route: "reports", step: "06", label: "Reports", detail: "누락 확인과 보고서 작성" },
    ],
  },
  {
    label: "Workspace",
    items: [
      { route: "directory", step: "", label: "AD Information", detail: "관찰 객체와 관계" },
      { route: "sessions", step: "", label: "Sessions", detail: "터널과 PTY 상태" },
      { route: "operations", step: "", label: "Operations", detail: "검색, 감사, 백업" },
    ],
  },
];

const pageNames = Object.fromEntries(
  pages.flatMap((group) => group.items.map((item) => [item.route, item.label])),
);

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`/api${path}`);
  if (!response.ok) throw new Error(response.statusText);
  return response.json();
}

export default function AppShell({
  route,
  children,
}: {
  route: string;
  children: ReactNode;
}) {
  const queryClient = useQueryClient();
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [paletteOpen, setPaletteOpen] = useState(false);
  const sidebarResize = useRef({x: 0, width: 264});
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    const saved = Number(localStorage.getItem("oscp-sidebar-width"));
    return saved >= sidebarMin && saved <= sidebarMax ? saved : 264;
  });
  const [sidebarCollapsed, setSidebarCollapsed] = useState(
    () => localStorage.getItem("oscp-sidebar-collapsed") === "true",
  );
  const [activeProjectId, setActiveProjectId] = useState(
    () => Number(localStorage.getItem("oscp-workspace-project")),
  );
  // Whichever workspace page is open (Service Enumeration, Scan Center, ...)
  // owns its own target selection and broadcasts it here, so the header
  // reflects what the user is actually looking at instead of always
  // guessing "the project's first target."
  const [activeTargetId, setActiveTargetId] = useState<number>();
  const projects = useQuery({ queryKey: ["projects"], queryFn: () => get<Project[]>("/projects") });
  const targets = useQuery({ queryKey: ["allTargets"], queryFn: () => get<Target[]>("/targets") });
  useEffect(() => {
    const change = (event: Event) =>
      setActiveProjectId((event as CustomEvent<number>).detail);
    addEventListener("oscp-project-change", change);
    return () => removeEventListener("oscp-project-change", change);
  }, []);
  useEffect(() => {
    const change = (event: Event) =>
      setActiveTargetId((event as CustomEvent<number>).detail);
    addEventListener("oscp-target-change", change);
    return () => removeEventListener("oscp-target-change", change);
  }, []);
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen(true);
      }
    };
    addEventListener("keydown", onKeyDown);
    return () => removeEventListener("keydown", onKeyDown);
  }, []);
  const project =
    projects.data?.find((item) => item.id === activeProjectId) || projects.data?.[0];
  const target =
    targets.data?.find((item) => item.id === activeTargetId && item.project_id === project?.id) ||
    targets.data?.find((item) => item.project_id === project?.id);
  const projectTargets = targets.data?.filter((item) => item.project_id === project?.id) || [];
  const projectTargetCount = projectTargets.length;
  // Fetched project-wide (not just the currently selected target) so the
  // command palette can point a tool search at whichever port actually has
  // a matching service, instead of only ever looking at what's on screen.
  const projectServices = useQuery({
    queryKey: ["projectServices", project?.id],
    queryFn: () => get<Service[]>(`/projects/${project?.id}/services`),
    enabled: !!project?.id,
  });
  const selectProject = (id: number) => {
    localStorage.setItem("oscp-workspace-project", String(id));
    setActiveProjectId(id);
    dispatchEvent(new CustomEvent("oscp-project-change", {detail: id}));
  };
  const setMetasploitLock = async (lockTargetId: number | null) => {
    if (!project) return;
    await fetch(`/api/projects/${project.id}/metasploit-lock`, {
      method: "PUT",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target_id: lockTargetId}),
    });
    await queryClient.invalidateQueries({queryKey: ["projects"]});
  };
  const applySidebarWidth = (width: number) => {
    const next = clampSidebar(width);
    setSidebarWidth(next);
    setSidebarCollapsed(false);
    localStorage.setItem("oscp-sidebar-width", String(next));
    localStorage.setItem("oscp-sidebar-collapsed", "false");
  };
  const toggleSidebar = () => {
    setSidebarCollapsed((collapsed) => {
      localStorage.setItem("oscp-sidebar-collapsed", String(!collapsed));
      return !collapsed;
    });
  };
  const beginSidebarResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    sidebarResize.current = {x: event.clientX, width: sidebarWidth};
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const resizeSidebar = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (!event.currentTarget.hasPointerCapture(event.pointerId)) return;
    applySidebarWidth(sidebarResize.current.width + event.clientX - sidebarResize.current.x);
  };
  const finishSidebarResize = (event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId))
      event.currentTarget.releasePointerCapture(event.pointerId);
  };

  const removeProject = async () => {
    if (!project) return;
    setDeleteBusy(true);
    setDeleteError("");
    try {
      const response = await fetch(`/api/projects/${project.id}`, {
        method: "DELETE",
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || response.statusText);
      }
      localStorage.removeItem("oscp-workspace-project");
      setActiveProjectId(0);
      // Deleting a project cascades to nearly every resource table on the
      // backend (scans, web requests, credentials, findings, ...), and a
      // recreated project/target can be assigned the same SQLite row id as
      // the one just removed — so every cached query, not just the project
      // and target lists, has to be dropped or a workspace tab left mounted
      // through the delete will keep showing the deleted project's data.
      await queryClient.invalidateQueries();
      setDeleteOpen(false);
      location.hash = "scans";
    } catch (reason) {
      setDeleteError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setDeleteBusy(false);
    }
  };

  return (
    <div
      className={`appShell${sidebarCollapsed ? " appShell--sidebarCollapsed" : ""}`}
      style={{
        "--sidebar-width": `${sidebarCollapsed ? sidebarCollapsedWidth : sidebarWidth}px`,
      } as CSSProperties}
    >
      <a className="skipLink" href="#workspace-content">본문으로 건너뛰기</a>
      <aside className="appSidebar">
        <div className="appSidebar__head">
          <a className="appBrand" href="#scans" aria-label="OSCP Workspace 홈">
            <span>OW</span>
            <strong>OSCP Workspace<small>local assessment desk</small></strong>
          </a>
          <button
            className="panelCollapseButton"
            type="button"
            aria-label={sidebarCollapsed ? "전체 메뉴 펼치기" : "전체 메뉴 접기"}
            aria-expanded={!sidebarCollapsed}
            title={sidebarCollapsed ? "전체 메뉴 펼치기" : "전체 메뉴 접기"}
            onClick={toggleSidebar}
          >{sidebarCollapsed ? "›" : "‹"}</button>
        </div>
        <nav aria-label="주요 작업">
          {pages.map((group) => (
            <section key={group.label}>
              <h2>{group.label}</h2>
              {group.items.map((item) => (
                <a
                  key={item.route}
                  href={`#${item.route}`}
                  aria-current={route === item.route ? "page" : undefined}
                >
                  <span>{item.step || "·"}</span>
                  <strong>{item.label}<small>{item.detail}</small></strong>
                </a>
              ))}
            </section>
          ))}
        </nav>
        <div className="policyNote">
          <Badge status="connected">Local only</Badge>
          <p>명령은 검토와 명시적 승인을 거친 뒤 실행됩니다.</p>
        </div>
        {!sidebarCollapsed && <div
          className="layoutResizeHandle appSidebar__resizeHandle"
          role="separator"
          aria-label="전체 메뉴 너비 조절"
          aria-orientation="vertical"
          aria-valuemin={sidebarMin}
          aria-valuemax={sidebarMax}
          aria-valuenow={sidebarWidth}
          title="드래그하거나 마우스 휠·방향키로 너비 조절"
          tabIndex={0}
          onPointerDown={beginSidebarResize}
          onPointerMove={resizeSidebar}
          onPointerUp={finishSidebarResize}
          onPointerCancel={finishSidebarResize}
          onWheel={(event) => {
            event.preventDefault();
            applySidebarWidth(sidebarWidth + (event.deltaY < 0 ? 16 : -16));
          }}
          onKeyDown={(event) => {
            if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
            event.preventDefault();
            if (event.key === 'Home') applySidebarWidth(sidebarMin);
            else if (event.key === 'End') applySidebarWidth(sidebarMax);
            else applySidebarWidth(sidebarWidth + (event.key === 'ArrowRight' ? 16 : -16));
          }}
        />}
      </aside>
      <div className="appFrame">
        <header className="contextBar">
          <label className="contextProject">
            <span>현재 프로젝트</span>
            <select
              aria-label="현재 프로젝트"
              value={project?.id || ""}
              disabled={!projects.data?.length}
              onChange={(event) => selectProject(Number(event.target.value))}
            >
              {!projects.data?.length && <option value="">프로젝트 없음</option>}
              {projects.data?.map((item) => (
                <option key={item.id} value={item.id}>{item.name}</option>
              ))}
            </select>
          </label>
          <Button
            variant="quiet"
            className="contextDelete"
            disabled={!project}
            onClick={() => {
              setDeleteError("");
              setDeleteOpen(true);
            }}
          >
            프로젝트 삭제
          </Button>
          <i aria-hidden="true" />
          <div>
            <span>현재 Target</span>
            <strong>{target ? `${target.name} · ${target.ip}` : "Target 없음"}</strong>
          </div>
          <div className="contextBar__page">
            <span>현재 작업</span>
            <strong>{pageNames[route] || "Scan Center"}</strong>
          </div>
          <Button
            type="button"
            variant="quiet"
            className="paletteTrigger"
            onClick={() => setPaletteOpen(true)}
          >
            검색<kbd>Ctrl K</kbd>
          </Button>
          <MetasploitLock project={project} targets={targets.data} targetId={target?.id}
            onSetLock={(id) => void setMetasploitLock(id)} />
          <VpnControl />
        </header>
        <div id="workspace-content" className="pageStage" tabIndex={-1}>
          {(projects.isLoading || targets.isLoading) && <LoadingState label="작업 컨텍스트 불러오는 중" />}
          {(projects.error || targets.error) && (
            <ErrorState message="백엔드 연결과 실행 상태를 확인하세요." />
          )}
          {children}
        </div>
        {paletteOpen && (
          <CommandPalette
            onClose={() => setPaletteOpen(false)}
            services={projectServices.data}
            targets={projectTargets}
          />
        )}
        {deleteOpen && project && (
          <div className="modal" role="presentation">
            <div
              role="dialog"
              aria-modal="true"
              aria-labelledby="delete-project-title"
              aria-describedby="delete-project-description"
            >
              <span>되돌릴 수 없는 작업</span>
              <h2 id="delete-project-title">프로젝트 삭제</h2>
              <p id="delete-project-description">
                <b>{project.name}</b>과 연결된 Target {projectTargetCount}개,
                스캔, 서비스 기록, Evidence, 보고서가 데이터베이스와
                워크스페이스 디렉터리에서 함께 삭제됩니다.
              </p>
              {deleteError && <p className="webError" role="alert">{deleteError}</p>}
              <footer>
                <Button
                  disabled={deleteBusy}
                  onClick={() => setDeleteOpen(false)}
                >
                  취소
                </Button>
                <Button
                  variant="danger"
                  autoFocus
                  disabled={deleteBusy}
                  onClick={removeProject}
                >
                  {deleteBusy ? "삭제 중…" : "삭제"}
                </Button>
              </footer>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
