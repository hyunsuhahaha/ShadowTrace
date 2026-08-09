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
  anchorId?: string;
  executionId?: number;
};

let pending: PendingServiceNav | undefined;

export function setPendingServiceNav(nav: PendingServiceNav) {
  pending = nav;
}

export function consumePendingServiceNav(): PendingServiceNav | undefined {
  const value = pending;
  pending = undefined;
  return value;
}
