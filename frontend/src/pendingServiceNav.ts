// A cross-target command palette pick needs to reach the Service
// Enumeration page's target/service selection, which is private component
// state (not URL-addressable). This module-level handoff survives both
// paths that can happen after a pick: a fresh mount (navigating in from a
// different route) and an already-mounted page (picking a different
// service while already on Service Enumeration) — see App.tsx's
// "oscp-service-nav" listener and its mount effect.
export type PendingServiceNav = {
  targetId: number;
  serviceId: number;
  projectId: number;
  anchorId?: string;
};

let pending: PendingServiceNav | undefined;

export function setPendingServiceNav(nav: PendingServiceNav) {
  pending = nav;
}

// Discards (instead of applying) a nav queued for a project other than the
// one now active. This module-level handoff survives the full <AppShell>
// remount that "oscp-project-change" triggers, so without this check a pick
// made just before switching projects could still land a stale
// target/service from the old project into the new project's Enumeration
// screen once its route finally mounts -- the destination page's own
// targetId state has no other way to know the nav predates the switch.
// "oscp-workspace-project" is read directly (not passed in) because it's
// the single synchronous source of truth for the active project used
// throughout the app -- see docs/ENGINEERING_ONBOARDING.md §12.2.
export function consumePendingServiceNav(): PendingServiceNav | undefined {
  const value = pending;
  pending = undefined;
  if (!value) return undefined;
  const activeProjectId = Number(localStorage.getItem("oscp-workspace-project"));
  return value.projectId === activeProjectId ? value : undefined;
}
