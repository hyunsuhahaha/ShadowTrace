import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  useEffect, useRef, useState,
  type CSSProperties, type PointerEvent as ReactPointerEvent, type ReactNode,
} from "react";
import { Button, ErrorState, LoadingState } from "./ui";
import VpnControl from "./VpnControl";
import MetasploitLock from "./MetasploitLock";
import CommandPalette from "./CommandPalette";
import {FloatingTerminalProvider} from "./FloatingTerminal";
import "./layout-controls.css";

type Project = { id: number; name: string; metasploit_target_id?: number | null };
type Target = { id: number; project_id: number; name: string; ip: string };

// Custom project-switcher dropdown (per-project delete X + add row).
const PM: Record<string, CSSProperties> = {
  button: { background: "transparent", border: "none", color: "#e7e7ee",
    font: "inherit", fontSize: 16, fontWeight: 600, cursor: "pointer",
    display: "flex", alignItems: "center", gap: 6, padding: 0 },
  menu: { position: "absolute", top: "100%", left: 0, marginTop: 6, minWidth: 240,
    background: "#16161c", border: "1px solid #2a2a34", borderRadius: 10, padding: 6,
    zIndex: 50, boxShadow: "0 12px 30px rgba(0,0,0,.5)" },
  row: { display: "flex", alignItems: "center", gap: 4 },
  name: { flex: 1, textAlign: "left", background: "transparent", border: "none",
    color: "#c9c9d2", font: "inherit", fontSize: 13, padding: "7px 8px",
    borderRadius: 6, cursor: "pointer" },
  del: { background: "transparent", border: "none", color: "#8b8b93", fontSize: 18,
    lineHeight: 1, cursor: "pointer", padding: "2px 8px", borderRadius: 6 },
  add: { width: "100%", textAlign: "left", background: "transparent", border: "none",
    borderTop: "1px solid #2a2a34", marginTop: 4, color: "#6aa9ff", font: "inherit",
    fontSize: 13, fontWeight: 600, padding: "8px", cursor: "pointer" },
};
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
      { route: "scans", step: "01", label: "Scan Center" },
      { route: "enumeration", step: "02", label: "Service Enumeration" },
      { route: "web", step: "03", label: "Web Testing · Intruder" },
      { route: "exploit-research", step: "04", label: "Exploit Research" },
      { route: "runbooks", step: "", label: "Runbooks" },
      { route: "post-exploitation", step: "", label: "Post-Exploitation" },
      { route: "hash-cracking", step: "", label: "Hash Cracking" },
      { route: "tools", step: "", label: "Tools" },
    ],
  },
  {
    label: "Document",
    items: [
      { route: "evidence", step: "05", label: "Evidence" },
      { route: "reports", step: "06", label: "Reports" },
      { route: "graph", step: "", label: "Progress Graph" },
    ],
  },
  {
    label: "Workspace",
    items: [
      { route: "directory", step: "", label: "AD Information" },
      { route: "sessions", step: "", label: "Sessions" },
      { route: "operations", step: "", label: "Operations" },
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
  const [pendingDelete, setPendingDelete] = useState<Project | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const [creatingProject, setCreatingProject] = useState(false);
  const [newProjectName, setNewProjectName] = useState("");
  const [createError, setCreateError] = useState("");
  const [createBusy, setCreateBusy] = useState(false);
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
  // Falling back to the first project above is display-only -- it never
  // touches localStorage/activeProjectId, so any other component that reads
  // "current project" straight from localStorage (e.g. GraphWorkspace's
  // useActiveProjectId) still sees "no project" and renders its own
  // no-project state even while the header shows a project name. Persisting
  // the fallback through the same path a manual selection takes keeps every
  // consumer in sync.
  useEffect(() => {
    if (project && project.id !== activeProjectId) selectProject(project.id);
  }, [project, activeProjectId]);
  const target =
    targets.data?.find((item) => item.id === activeTargetId && item.project_id === project?.id) ||
    targets.data?.find((item) => item.project_id === project?.id);
  const projectTargets = targets.data?.filter((item) => item.project_id === project?.id) || [];
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
  // In-app modal instead of window.prompt()/alert() -- those are native OS
  // dialogs, not something this app renders, and on Linux (esp. Chrome run
  // as root or without a full window manager, e.g. a bare Kali VM) they can
  // fail to surface at all: the call just returns null/undefined with zero
  // visible sign anything happened, which reads exactly like "the button
  // doesn't do anything." The same silent-null failure also happens on any
  // OS once a browser has been told to block a site's dialogs. An in-app
  // modal is plain DOM, so none of that applies.
  const openCreateProject = () => {
    setNewProjectName(`OSCP Practice ${Date.now().toString().slice(-4)}`);
    setCreateError("");
    setCreatingProject(true);
  };
  const submitCreateProject = async () => {
    const trimmed = newProjectName.trim();
    if (!trimmed) { setCreateError("이름을 입력하세요."); return; }
    setCreateBusy(true);
    setCreateError("");
    try {
      const response = await fetch("/api/projects", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({name: trimmed, description: "Local lab workspace"}),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || response.statusText);
      }
      const created = await response.json();
      await queryClient.invalidateQueries({queryKey: ["projects"]});
      selectProject(created.id);
      setCreatingProject(false);
    } catch (reason) {
      setCreateError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setCreateBusy(false);
    }
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
    const victim = pendingDelete;
    if (!victim) return;
    setDeleteBusy(true);
    setDeleteError("");
    try {
      const response = await fetch(`/api/projects/${victim.id}`, {
        method: "DELETE",
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || response.statusText);
      }
      if (victim.id === activeProjectId) {
        localStorage.removeItem("oscp-workspace-project");
        setActiveProjectId(0);
        // Notify listeners (e.g. the Progress Graph) that there is no active
        // project now, so they reset instead of keeping the deleted project's id.
        dispatchEvent(new CustomEvent("oscp-project-change", { detail: 0 }));
      }
      // Deleting a project cascades to nearly every resource table on the
      // backend (scans, web requests, credentials, findings, ...), and a
      // recreated project/target can be assigned the same SQLite row id as
      // the one just removed — so every cached query, not just the project
      // and target lists, has to be dropped or a workspace tab left mounted
      // through the delete will keep showing the deleted project's data.
      queryClient.removeQueries({ queryKey: ["graph"] });
      queryClient.removeQueries({ queryKey: ["graphTree"] });
      await queryClient.invalidateQueries();
      setPendingDelete(null);
    } catch (reason) {
      setDeleteError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setDeleteBusy(false);
    }
  };

  return <FloatingTerminalProvider>
    <div
      className={`appShell${sidebarCollapsed ? " appShell--sidebarCollapsed" : ""}`}
      style={{
        "--sidebar-width": `${sidebarCollapsed ? sidebarCollapsedWidth : sidebarWidth}px`,
      } as CSSProperties}
    >
      <a className="skipLink" href="#workspace-content">본문으로 건너뛰기</a>
      <aside className="appSidebar">
        <div className="appSidebar__head">
          <a className="appBrand" href="#scans" aria-label="ShadowTrace 홈">
            <span>ST</span>
            <strong>ShadowTrace</strong>
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
                  <strong>{item.label}</strong>
                </a>
              ))}
            </section>
          ))}
        </nav>
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
          <div className="contextProject" style={{position: "relative"}}>
            <span>현재 프로젝트</span>
            <button type="button" style={PM.button}
              onClick={() => setMenuOpen((open) => !open)}>
              <span className="contextPrompt" aria-hidden="true">&gt;</span>
              {project?.name || "프로젝트 없음"} <span aria-hidden="true">▾</span>
            </button>
            {menuOpen && (
              <>
                <div style={{position: "fixed", inset: 0, zIndex: 40}}
                  onClick={() => setMenuOpen(false)} />
                <div style={PM.menu} role="menu">
                  {projects.data?.map((item) => (
                    <div key={item.id} style={PM.row}>
                      <button type="button" role="menuitem"
                        style={{...PM.name, ...(item.id === project?.id
                          ? {color: "#e7e7ee", fontWeight: 600} : {})}}
                        onClick={() => { selectProject(item.id); setMenuOpen(false); }}>
                        {item.name}
                      </button>
                      <button type="button" aria-label={`${item.name} 삭제`} style={PM.del}
                        onClick={() => { setDeleteError(""); setPendingDelete(item); setMenuOpen(false); }}>
                        ×
                      </button>
                    </div>
                  ))}
                  {!projects.data?.length && (
                    <div style={{padding: "8px 10px", color: "#6b6b76", fontSize: 12}}>
                      프로젝트 없음
                    </div>
                  )}
                  <button type="button" style={PM.add} disabled={createBusy}
                    onClick={() => { setMenuOpen(false); openCreateProject(); }}>
                    ＋ 새 프로젝트 추가
                  </button>
                </div>
              </>
            )}
          </div>
          <i aria-hidden="true" />
          <div>
            <span>현재 Target</span>
            <strong>{target ? target.name && target.name !== target.ip
              ? `${target.name} · ${target.ip}` : target.ip : "Target 없음"}</strong>
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
        {pendingDelete && (
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
                <b>{pendingDelete.name}</b>과 연결된 Target{" "}
                {targets.data?.filter((t) => t.project_id === pendingDelete.id).length ?? 0}개,
                스캔, 서비스 기록, Evidence, 보고서가 데이터베이스와
                워크스페이스 디렉터리에서 함께 삭제됩니다.
              </p>
              {deleteError && <p className="webError" role="alert">{deleteError}</p>}
              <footer>
                <Button
                  disabled={deleteBusy}
                  onClick={() => setPendingDelete(null)}
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
        {creatingProject && (
          <div className="modal" role="presentation">
            <div
              role="dialog"
              aria-modal="true"
              aria-labelledby="create-project-title"
            >
              <span>새 프로젝트</span>
              <h2 id="create-project-title">프로젝트 추가</h2>
              <label htmlFor="new-project-name">이름</label>
              <input
                id="new-project-name"
                autoFocus
                value={newProjectName}
                disabled={createBusy}
                onChange={(e) => setNewProjectName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") { e.preventDefault(); void submitCreateProject(); }
                }}
              />
              {createError && <p className="webError" role="alert">{createError}</p>}
              <footer>
                <Button
                  disabled={createBusy}
                  onClick={() => setCreatingProject(false)}
                >
                  취소
                </Button>
                <Button
                  variant="primary"
                  disabled={createBusy || !newProjectName.trim()}
                  onClick={() => void submitCreateProject()}
                >
                  {createBusy ? "만드는 중…" : "추가"}
                </Button>
              </footer>
            </div>
          </div>
        )}
      </div>
    </div>
  </FloatingTerminalProvider>;
}
