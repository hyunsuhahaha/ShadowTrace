import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import InteractiveTerminal from "./InteractiveTerminal";
type Project = { id: number; name: string; description: string };
type Target = {
  id: number;
  project_id: number;
  name: string;
  ip: string;
  hostname: string;
  os_guess: string;
  vpn: string;
  notes: string;
};
type Service = {
  id: number;
  target_id: number;
  port: number;
  protocol: string;
  state: string;
  name: string;
  product: string;
  version: string;
  extra_info: string;
  scripts: string;
  notes: string;
  tags: string;
};
const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const r = await fetch("/api" + path, init);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.status === 204 ? (null as T) : r.json();
};
export default function App() {
  const qc = useQueryClient();
  const [projectId, setProjectId] = useState<number>();
  const [targetId, setTargetId] = useState<number>();
  const [serviceId, setServiceId] = useState<number>();
  const [output, setOutput] = useState(
    "Select a service and run a reviewed command.\n",
  );
  const [confirm, setConfirm] = useState<any>();
  const [serviceNotes, setServiceNotes] = useState("");
  const [serviceTags, setServiceTags] = useState("");
  const [terminalSession, setTerminalSession] = useState<number>();
  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: () => api<Project[]>("/projects"),
  });
  const targets = useQuery({
    queryKey: ["targets", projectId],
    queryFn: () => api<Target[]>(`/targets?project_id=${projectId}`),
    enabled: !!projectId,
  });
  const services = useQuery({
    queryKey: ["services", targetId],
    queryFn: () => api<Service[]>(`/targets/${targetId}/services`),
    enabled: !!targetId,
  });
  const commands = useQuery({
    queryKey: ["commands", serviceId],
    queryFn: () => api<any[]>(`/services/${serviceId}/commands`),
    enabled: !!serviceId,
  });
  const executions = useQuery({
    queryKey: ["executions", targetId],
    queryFn: () => api<any[]>(`/executions?target_id=${targetId}`),
    enabled: !!targetId,
    refetchInterval: 3000,
  });
  const status = useQuery({
    queryKey: ["status"],
    queryFn: () => api<any>("/system/status"),
  });
  useEffect(() => {
    if (!projectId && projects.data?.[0]) setProjectId(projects.data[0].id);
  }, [projects.data]);
  useEffect(() => {
    setTargetId(targets.data?.[0]?.id);
  }, [projectId, targets.data]);
  useEffect(() => {
    setServiceId(services.data?.[0]?.id);
  }, [targetId, services.data]);
  useEffect(() => {
    const selected = services.data?.find((x) => x.id === serviceId) as any;
    setServiceNotes(selected?.notes || "");
    try {
      setServiceTags(JSON.parse(selected?.tags || "[]").join(", "));
    } catch {
      setServiceTags("");
    }
  }, [serviceId, services.data]);
  const project = projects.data?.find((x) => x.id === projectId),
    target = targets.data?.find((x) => x.id === targetId),
    service = services.data?.find((x) => x.id === serviceId);
  const createProject = useMutation({
    mutationFn: () =>
      api<Project>("/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: `OSCP Practice ${Date.now().toString().slice(-4)}`,
          description: "Local lab workspace",
        }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["projects"] }),
  });
  const createTarget = useMutation({
    mutationFn: () =>
      api<Target>("/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_id: projectId,
          name: "New target",
          ip: prompt("Target IP", "10.10.10.10") || "",
          hostname: "",
          os_guess: "",
          vpn: "tun0",
          notes: "",
        }),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["targets"] }),
  });
  const run = async () => {
    const c = confirm;
    if (!c || !targetId) return;
    setConfirm(null);
    if (c.execution_mode === "interactive") {
      const variables: any = {};
      if (c.command.includes("{username}")) {
        const username = prompt(
          "Username (authentication remains interactive)",
          "",
        );
        if (!username) return;
        variables.username = username;
      }
      const session = await api<any>("/interactive-sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_id: targetId,
          service_id: serviceId,
          template_id: c.id,
          variables,
        }),
      });
      setTerminalSession(session.id);
      return;
    }
    setOutput(`$ ${c.preview}\n`);
    const e = await api<any>("/executions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_id: targetId,
        service_id: serviceId,
        template_id: c.id,
        variables: {},
      }),
    });
    const s = new EventSource(`/api/executions/${e.id}/events`);
    s.onmessage = (ev) => {
      const d = JSON.parse(ev.data);
      if (d.stream === "status") {
        setOutput(
          (x) =>
            x +
            `\n[${d.status}${d.exit_code == null ? "" : ` · exit ${d.exit_code}`}]`,
        );
        s.close();
        qc.invalidateQueries({ queryKey: ["executions", targetId] });
      } else setOutput((x) => x + d.data);
    };
  };
  const saveService = async () => {
    if (!serviceId) return;
    await api(`/services/${serviceId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        notes: serviceNotes,
        tags: serviceTags
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean),
      }),
    });
    qc.invalidateQueries({ queryKey: ["services", targetId] });
  };
  const openExecution = async (id: number) => {
    const data = await api<any>(`/executions/${id}/output`);
    setOutput(
      data.stdout +
        data.stderr +
        `\n[${data.status}${data.exit_code == null ? "" : ` · exit ${data.exit_code}`}]`,
    );
  };
  const upload = async (f: File) => {
    if (!targetId) return;
    const d = new FormData();
    d.append("file", f);
    await api(`/targets/${targetId}/nmap`, { method: "POST", body: d });
    qc.invalidateQueries({ queryKey: ["services", targetId] });
  };
  const vpn = status.data?.vpn;
  const missing = status.data?.tools?.filter((x: any) => !x.installed).length;
  return (
    <div className="app">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>Local enumeration cockpit</small>
          </div>
        </div>
        <div className="target">
          <span>PROJECT</span>
          <b>{project?.name || "No project"}</b>
          <i>/</i>
          <span>TARGET</span>
          <b>{target?.ip || "—"}</b>
        </div>
        <div className={`vpn ${vpn?.connected ? "ok" : ""}`}>
          <span className="dot" />
          {vpn?.connected ? "tun0 connected" : "VPN offline"}
          <small>{vpn?.tun0 || "No tunnel address"}</small>
        </div>
      </header>
      <nav>
        <button onClick={() => createProject.mutate()}>＋ Project</button>
        <select
          value={projectId || ""}
          onChange={(e) => setProjectId(+e.target.value)}
        >
          <option value="">Select project</option>
          {projects.data?.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <button disabled={!projectId} onClick={() => createTarget.mutate()}>
          ＋ Target
        </button>
        <select
          value={targetId || ""}
          onChange={(e) => setTargetId(+e.target.value)}
        >
          <option value="">Select target</option>
          {targets.data?.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} · {t.ip}
            </option>
          ))}
        </select>
        <label className="upload">
          Import Nmap XML
          <input
            type="file"
            accept=".xml"
            onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])}
          />
        </label>
        <span className="tools">{missing ?? "—"} tools missing</span>
      </nav>
      <main>
        <aside className="services">
          <div className="panelTitle">
            <span>SERVICES</span>
            <em>{services.data?.length || 0} open</em>
          </div>
          {services.data?.map((s) => (
            <button
              className={s.id === serviceId ? "active" : ""}
              key={s.id}
              onClick={() => setServiceId(s.id)}
            >
              <strong>{s.port}</strong>
              <span>
                {s.name.toUpperCase()}
                <small>{s.product || "Unidentified service"}</small>
              </span>
              <i>{s.protocol}</i>
            </button>
          ))}
          {!services.data?.length && (
            <div className="empty">
              Import an Nmap XML scan to populate the service map.
            </div>
          )}
        </aside>
        <section className="work">
          <div className="serviceHead">
            <div>
              <span>
                {service?.protocol || "tcp"} / {service?.port || "—"}
              </span>
              <h1>{service?.name?.toUpperCase() || "Select a service"}</h1>
              <p>
                {[service?.product, service?.version, service?.extra_info]
                  .filter(Boolean)
                  .join(" · ") ||
                  "Service intelligence and reviewed commands appear here."}
              </p>
            </div>
            <div className="risk">MANUAL CONFIRMATION</div>
          </div>
          <div className="tabs">
            <b>COMMANDS</b>
            <span>SCAN DETAILS</span>
            <span>HISTORY</span>
          </div>
          <div className="cards">
            {commands.data?.map((c) => (
              <article key={c.id}>
                <div>
                  <span className="badge">{c.risk} risk</span>
                  <h3>{c.name}</h3>
                  <p>{c.description}</p>
                </div>
                <code>{c.preview}</code>
                <div className="actions">
                  <button
                    onClick={() => navigator.clipboard.writeText(c.preview)}
                  >
                    Copy
                  </button>
                  <button className="primary" onClick={() => setConfirm(c)}>
                    Review & run →
                  </button>
                </div>
              </article>
            ))}
          </div>
          <div className="terminal">
            <div>
              <span />
              <b>LIVE OUTPUT</b>
              <small>captured stdout / stderr</small>
            </div>
            <pre>{output}</pre>
          </div>
        </section>
        <aside className="notes">
          <div className="panelTitle">
            <span>SERVICE WORKSPACE</span>
            <em>local</em>
          </div>
          <div className="meta">
            <label>
              HOSTNAME<b>{target?.hostname || "Unknown"}</b>
            </label>
            <label>
              OS GUESS<b>{target?.os_guess || "Not detected"}</b>
            </label>
          </div>
          <h3>Enumeration checklist</h3>
          {[
            "Validate service banner",
            "Review default credentials policy",
            "Capture version evidence",
            "Record interesting paths",
            "Plan next manual step",
          ].map((x, i) => (
            <label className="check" key={x}>
              <input type="checkbox" />
              <span>{x}</span>
              <small>0{i + 1}</small>
            </label>
          ))}
          <h3>Service tags</h3>
          <input
            value={serviceTags}
            onChange={(e) => setServiceTags(e.target.value)}
            placeholder="web, reviewed"
          />
          <h3>Service notes</h3>
          <textarea
            value={serviceNotes}
            onChange={(e) => setServiceNotes(e.target.value)}
            placeholder="Markdown notes for this port…"
          />
          <button onClick={saveService}>Save workspace</button>
          <h3>Execution history</h3>
          <div className="executionHistory">
            {executions.data
              ?.filter((x) => x.service_id === serviceId)
              .map((x) => (
                <button key={x.id} onClick={() => openExecution(x.id)}>
                  <b>
                    #{x.id} {x.template_id}
                  </b>
                  <small>
                    {x.status}
                    {x.exit_code == null ? "" : ` · exit ${x.exit_code}`}
                  </small>
                </button>
              ))}
          </div>
          <div className="warning">
            <b>Scope guard</b>
            <p>
              Commands run on this Kali host. Verify authorization and the final
              command before execution.
            </p>
          </div>
        </aside>
      </main>
      {terminalSession && (
        <InteractiveTerminal
          sessionId={terminalSession}
          onClose={() => setTerminalSession(undefined)}
        />
      )}
      {confirm && (
        <div className="modal">
          <div>
            <span>FINAL COMMAND REVIEW</span>
            <h2>{confirm.name}</h2>
            <p>
              The command will execute locally without a shell. Confirm the
              target and options.
            </p>
            <code>{confirm.preview}</code>
            <label>
              <input type="checkbox" id="scope" /> I confirm this target is in
              scope.
            </label>
            <footer>
              <button onClick={() => setConfirm(null)}>Cancel</button>
              <button
                className="danger"
                onClick={() => {
                  const el = document.getElementById(
                    "scope",
                  ) as HTMLInputElement;
                  if (el.checked) run();
                }}
              >
                Execute command
              </button>
            </footer>
          </div>
        </div>
      )}
    </div>
  );
}
