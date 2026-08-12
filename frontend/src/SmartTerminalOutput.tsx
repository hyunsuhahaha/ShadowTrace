import {useMemo, useState, type MouseEvent, type ReactNode} from "react";
import {api} from "./api";
import {setPendingServiceNav} from "./pendingServiceNav";
import type {GraphNode, GraphOut} from "./features/graph/graphModel";
import "./smart-terminal.css";

export type TerminalMatch = {
  kind: "service" | "ip" | "url";
  value: string;
  start: number;
  end: number;
  port?: number;
  protocol?: string;
  service?: string;
};

export type SmartTerminalContext = {
  projectId?: number;
  targetId?: number;
  targetIp?: string;
  serviceId?: number;
};

const validIp = (value: string) => value.split(".").every((part) => Number(part) <= 255);

export function parseTerminalMatches(output: string): TerminalMatch[] {
  const found: TerminalMatch[] = [];
  const add = (match: TerminalMatch) => {
    if (!found.some((item) => match.start < item.end && match.end > item.start)) found.push(match);
  };
  for (const match of output.matchAll(/https?:\/\/[^\s<>"'`]+/gi)) {
    const raw = match[0].replace(/[),.;\]]+$/, "");
    add({kind: "url", value: raw, start: match.index!, end: match.index! + raw.length});
  }
  for (const match of output.matchAll(/^(\d{1,5})\/(tcp|udp)\s+open(?:\|filtered)?\s+([\w.-]+)/gmi)) {
    const port = Number(match[1]);
    if (port > 65535) continue;
    add({kind: "service", value: match[0], start: match.index!, end: match.index! + match[0].length,
      port, protocol: match[2].toLowerCase(), service: match[3]});
  }
  for (const match of output.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
    if (validIp(match[0])) add({kind: "ip", value: match[0], start: match.index!,
      end: match.index! + match[0].length});
  }
  return found.sort((a, b) => a.start - b.start);
}

function ref(node: GraphNode) {
  try { return JSON.parse(node.source_ref || "{}"); } catch { return {}; }
}

function inferredUrl(match: TerminalMatch, context: SmartTerminalContext) {
  if (match.kind === "url") return match.value;
  if (match.kind === "ip") return `http://${match.value}/`;
  const secure = match.port === 443 || match.port === 8443 || /https|ssl/i.test(match.service || "");
  return `${secure ? "https" : "http"}://${context.targetIp || "target"}:${match.port}/`;
}

export default function SmartTerminalOutput({output, context, cursor}: {
  output: string;
  context: SmartTerminalContext;
  cursor?: boolean;
}) {
  const matches = useMemo(() => parseTerminalMatches(output), [output]);
  const [menu, setMenu] = useState<{match: TerminalMatch; x: number; y: number}>();
  const [notice, setNotice] = useState("");

  const openMenu = (event: MouseEvent, match: TerminalMatch) => {
    event.preventDefault();
    event.stopPropagation();
    setMenu({match, x: event.clientX, y: event.clientY});
  };
  const addChild = async () => {
    const match = menu?.match;
    if (!match || !context.projectId || !context.targetId) return;
    setNotice("GRAPH SYNC…");
    try {
      await api(`/projects/${context.projectId}/graph/sync`, {method: "POST"});
      const graph = await api<GraphOut>(`/projects/${context.projectId}/graph`);
      const type = match.kind === "service" ? "service" : match.kind === "ip" ? "host" : "finding";
      const host = graph.nodes.find((node) =>
        ref(node).kind === "target" && Number(ref(node).id) === context.targetId);
      const serviceSource = graph.nodes.find((node) =>
        ref(node).kind === "service" && Number(ref(node).id) === context.serviceId);
      const source = type === "finding" && serviceSource ? serviceSource : host;
      if (!source) throw new Error("현재 Target의 그래프 노드를 찾지 못했습니다.");
      const label = match.kind === "service"
        ? `${match.port}/${match.protocol} ${match.service}` : match.value;
      const existing = graph.nodes.find((node) => node.type === type && node.label === label);
      if (existing) {
        setNotice(`EXISTS · ${label}`);
        setMenu(undefined);
        return;
      }
      const node = await api<{id: string}>(`/projects/${context.projectId}/graph/nodes`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({type, label, status: "untried",
          provenance: JSON.stringify({source: "terminal-parser", observedText: match.value})}),
      });
      await api(`/projects/${context.projectId}/graph/edges`, {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({source: source.id, target: node.id,
          relation: type === "finding" ? "enumerated" : "discovered"}),
      });
      dispatchEvent(new CustomEvent("oscp-graph-refresh"));
      setNotice(`ADDED · ${label}`);
      setMenu(undefined);
    } catch (reason) {
      setNotice(`FAILED · ${reason instanceof Error ? reason.message : reason}`);
    }
  };
  const stageFuzz = async () => {
    const match = menu?.match;
    if (!match || !context.targetId) return;
    try {
      const services = await api<Array<{id: number; port: number; name: string}>>(
        `/targets/${context.targetId}/services`);
      const url = new URL(inferredUrl(match, context));
      const port = match.port || Number(url.port) || (url.protocol === "https:" ? 443 : 80);
      const service = services.find((item) => item.id === context.serviceId || item.port === port);
      if (!service) throw new Error(`${port}/tcp Service를 먼저 그래프에 추가하세요.`);
      localStorage.setItem("oscp-smart-fuzz-url", url.toString());
      setPendingServiceNav({targetId: context.targetId, serviceId: service.id,
        anchorId: "fuzz-heading"});
      location.hash = "#enumeration";
      dispatchEvent(new CustomEvent("oscp-service-nav"));
      setMenu(undefined);
    } catch (reason) {
      setNotice(`FAILED · ${reason instanceof Error ? reason.message : reason}`);
    }
  };
  const openBrowser = () => {
    if (!menu) return;
    window.open(inferredUrl(menu.match, context), "_blank", "noopener,noreferrer");
    setMenu(undefined);
  };

  const parts: ReactNode[] = [];
  let offset = 0;
  for (const match of matches) {
    parts.push(output.slice(offset, match.start));
    parts.push(<button key={`${match.start}:${match.value}`} type="button"
      className={`smartTerminal__token smartTerminal__token--${match.kind}`}
      title="Smart actions" onClick={(event) => openMenu(event, match)}
      onContextMenu={(event) => openMenu(event, match)}>{match.value}</button>);
    offset = match.end;
  }
  parts.push(output.slice(offset));

  return <>
    <code className="smartTerminal__output">{parts}</code>
    {cursor && <i className="scanTranscript__cursor" aria-hidden="true" />}
    {notice && <span className="smartTerminal__notice" role="status">{notice}</span>}
    {menu && <div className="smartTerminal__backdrop" onClick={() => setMenu(undefined)}>
      <menu className="smartTerminal__menu" style={{left: menu.x, top: menu.y}}
        onClick={(event) => event.stopPropagation()} aria-label={`${menu.match.value} smart actions`}>
        <header><span>PARSED · {menu.match.kind.toUpperCase()}</span><code>{menu.match.value}</code></header>
        <button type="button" disabled={!context.projectId || !context.targetId} onClick={addChild}>
          ＋ ADD AS CHILD NODE</button>
        <button type="button" onClick={openBrowser}>🌐 OPEN IN BROWSER</button>
        {(menu.match.kind === "url" || menu.match.kind === "service") &&
          <button type="button" disabled={!context.targetId} onClick={stageFuzz}>🚀 STAGE FEROX / FFUF</button>}
        <button type="button" onClick={() => setMenu(undefined)}>ESC · DISMISS</button>
      </menu>
    </div>}
  </>;
}
