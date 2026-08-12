import {useQuery} from "@tanstack/react-query";
import {api} from "../../api";
import {nodeMeta, type GraphNode} from "./graphModel";
import "./project-operator-session.css";

const targetId = (node: GraphNode) => {
  try {
    const ref = JSON.parse(node.source_ref || "{}");
    return ref.kind === "target" ? Number(ref.id) : undefined;
  } catch { return undefined; }
};

export default function ProjectOperatorSession({project, nodes, onSelect}: {
  project: GraphNode;
  nodes: GraphNode[];
  onSelect: (nodeId: string) => void;
}) {
  const vpn = useQuery({queryKey: ["vpnStatus"], queryFn: () => api<any>("/vpn/status"),
    refetchInterval: 3000});
  const targets = nodes.filter((node) => node.type === "host" && targetId(node));
  const sessions = nodes.filter((node) => node.type === "technique");
  const findings = nodes.filter((node) => node.type === "finding");
  const services = nodes.filter((node) => node.type === "service");
  const recent = [...sessions].sort((a, b) =>
    String(b.updated_at || b.created_at || "").localeCompare(String(a.updated_at || a.created_at || "")))
    .slice(0, 6);

  return <section className="projectOperator" aria-label="프로젝트 오퍼레이터 세션">
    <header><span className="termDots" aria-hidden="true"><i className="termDot" />
      <i className="termDot termDot--yellow" /><i className="termDot termDot--green" /></span>
      <div><small>PROJECT OPERATOR SESSION</small>
        <strong>project://{project.label}</strong></div>
      <em>{vpn.data?.connected ? `${vpn.data.link_type || "tun0"} ONLINE` : "IFACE OFFLINE"}</em>
    </header>
    <dl className="projectOperator__facts">
      <div><dt>TARGETS</dt><dd>{targets.length}</dd></div>
      <div><dt>SERVICES</dt><dd>{services.length}</dd></div>
      <div><dt>SESSIONS</dt><dd>{sessions.length}</dd></div>
      <div><dt>FINDINGS</dt><dd>{findings.length}</dd></div>
    </dl>
    <section className="projectOperator__targets">
      <header><span>AVAILABLE TARGET CONTEXTS</span><small>{targets.length} bound</small></header>
      {targets.length ? targets.map((target, index) => <button key={target.id}
        type="button" onClick={() => onSelect(target.id)}>
        <span>{String(index + 1).padStart(2, "0")}</span><b>&gt;</b>
        <strong>target://{target.label}</strong><em>{target.status}</em>
      </button>) : <p>$ no target context · add or import a Target first</p>}
    </section>
    <section className="projectOperator__recent">
      <header><span>RECENT SESSION BUFFER</span><small>{recent.length} entries</small></header>
      {recent.length ? recent.map((session) => {
        const meta = nodeMeta(session);
        return <button key={session.id} type="button" onClick={() => onSelect(session.id)}>
          <i className={`is-${session.status}`} /><span>{session.label}</span>
          <code>{meta.executionStatus || session.status}</code>
        </button>;
      }) : <p># no executions recorded</p>}
    </section>
    <footer><b>$</b><span>select target &lt;context&gt;</span>
      <small>root scope routes sessions; it does not execute commands</small></footer>
  </section>;
}
