import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

type Target = { id: number; name: string; ip: string };
type Profile = {
  id: number;
  name: string;
  kind: string;
  description: string;
  arguments: string;
};
type Scan = {
  id: number;
  source: string;
  status: string;
  command: string;
  created_at: string;
  started_at?: string;
  ended_at?: string;
  exit_code?: number;
  error: string;
  alias: string;
  tags: string;
};
type Obs = {
  id: number;
  port: number;
  protocol: string;
  state: string;
  name: string;
  product: string;
  version: string;
  extra_info: string;
  scripts: string;
};
type Artifact = {
  id: number;
  kind: string;
  sha256: string;
  size: number;
  original_name: string;
};
const terminal = ["completed", "failed", "stopped", "interrupted"];
const get = async <T,>(path: string): Promise<T> => {
  const r = await fetch("/api" + path);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};
const elapsed = (s: Scan) => {
  const seconds = Math.max(
    0,
    Math.floor(
      (Date.parse(s.ended_at || new Date().toISOString()) -
        Date.parse(s.started_at || s.created_at)) /
        1000,
    ),
  );
  return seconds < 60
    ? `${seconds}s`
    : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
};
const bytes = (n: number) =>
  n < 1024
    ? `${n} B`
    : n < 1048576
      ? `${(n / 1024).toFixed(1)} KiB`
      : `${(n / 1048576).toFixed(1)} MiB`;

export default function ScanCenter() {
  const qc = useQueryClient();
  const [targetId, setTargetId] = useState<number>(),
    [scanId, setScanId] = useState<number>(),
    [baseId, setBaseId] = useState<number>(),
    [profileId, setProfileId] = useState<number>(),
    [ports, setPorts] = useState("80,443"),
    [review, setReview] = useState(false),
    [scope, setScope] = useState(false),
    [output, setOutput] = useState("Select a scan to open its saved output.\n"),
    [statusFilter, setStatusFilter] = useState("all"),
    [query, setQuery] = useState(""),
    [serviceFilter, setServiceFilter] = useState(""),
    [portFilter, setPortFilter] = useState(""),
    [openOnly, setOpenOnly] = useState(false),
    [changedOnly, setChangedOnly] = useState(false),
    [sort, setSort] = useState<"port" | "service">("port");
  const targets = useQuery({
      queryKey: ["allTargets"],
      queryFn: () => get<Target[]>("/targets"),
    }),
    profiles = useQuery({
      queryKey: ["scanProfiles"],
      queryFn: () => get<Profile[]>("/scans/profiles"),
    }),
    scans = useQuery({
      queryKey: ["scans", targetId],
      queryFn: () => get<Scan[]>(`/scans?target_id=${targetId}`),
      enabled: !!targetId,
      refetchInterval: 3000,
    }),
    obs = useQuery({
      queryKey: ["scanObs", scanId],
      queryFn: () => get<Obs[]>(`/scans/${scanId}/observations`),
      enabled: !!scanId,
    }),
    artifacts = useQuery({
      queryKey: ["scanArtifacts", scanId],
      queryFn: () => get<Artifact[]>(`/scans/${scanId}/artifacts`),
      enabled: !!scanId,
    }),
    diff = useQuery({
      queryKey: ["scanDiff", baseId, scanId],
      queryFn: () => get<any>(`/scans/compare/${baseId}/${scanId}`),
      enabled: !!baseId && !!scanId && baseId !== scanId,
    });
  useEffect(() => {
    if (!targetId && targets.data?.[0]) setTargetId(targets.data[0].id);
  }, [targets.data, targetId]);
  useEffect(() => {
    if (scans.data?.length && !scans.data.some((s) => s.id === scanId))
      setScanId(scans.data[0].id);
  }, [scans.data, scanId]);
  useEffect(() => {
    if (!profileId && profiles.data?.[0]) setProfileId(profiles.data[0].id);
  }, [profiles.data, profileId]);
  const profile = profiles.data?.find((x) => x.id === profileId),
    target = targets.data?.find((x) => x.id === targetId),
    selected = scans.data?.find((x) => x.id === scanId),
    payload = () => ({
      target_id: targetId,
      profile_id: profileId,
      ports: profile?.kind === "selected_ports" ? ports : "",
      extra_arguments: [],
    });
  const preview = useQuery({
    queryKey: ["scanPreview", targetId, profileId, ports],
    queryFn: async () => {
      const r = await fetch("/api/scans/preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload()),
      });
      if (!r.ok) throw new Error((await r.json()).detail);
      return r.json();
    },
    enabled: !!targetId && !!profileId,
  });
  useEffect(() => {
    if (!scanId) return;
    setOutput("");
    const events = new EventSource(`/api/scans/${scanId}/events`);
    events.onmessage = async (e) => {
      const item = JSON.parse(e.data);
      if (item.stream === "snapshot") setOutput(item.data);
      if (item.stream === "stdout") setOutput((v) => v + item.data);
      if (item.stream === "stderr")
        setOutput((v) => v + `[stderr] ${item.data}`);
      if (item.stream === "status" && terminal.includes(item.status)) {
        setOutput(
          (v) =>
            v +
            (item.error
              ? `\n[${item.status}] ${item.error}\n`
              : `\n[${item.status}${item.exit_code == null ? "" : ` · exit ${item.exit_code}`}]\n`),
        );
        events.close();
        await qc.invalidateQueries({ queryKey: ["scans", targetId] });
        await qc.invalidateQueries({ queryKey: ["scanObs", scanId] });
        await qc.invalidateQueries({ queryKey: ["scanArtifacts", scanId] });
      }
    };
    events.onerror = () => events.close();
    return () => events.close();
  }, [scanId, targetId, qc]);
  const visibleScans = useMemo(
      () =>
        (scans.data || []).filter(
          (s) =>
            (statusFilter === "all" || s.status === statusFilter) &&
            (!query ||
              `${s.id} ${s.alias} ${s.command} ${s.tags}`
                .toLowerCase()
                .includes(query.toLowerCase())),
        ),
      [scans.data, statusFilter, query],
    ),
    changedPorts = useMemo(
      () =>
        new Set<string>(
          (diff.data?.changed || []).map((x: any) => `${x.protocol}:${x.port}`),
        ),
      [diff.data],
    ),
    visibleObs = useMemo(
      () =>
        (obs.data || [])
          .filter(
            (o) =>
              (!openOnly || o.state === "open") &&
              (!serviceFilter ||
                o.name.toLowerCase().includes(serviceFilter.toLowerCase())) &&
              (!portFilter || String(o.port).includes(portFilter)) &&
              (!changedOnly || changedPorts.has(`${o.protocol}:${o.port}`)),
          )
          .sort((a, b) =>
            sort === "port"
              ? a.port - b.port
              : a.name.localeCompare(b.name) || a.port - b.port,
          ),
      [
        obs.data,
        openOnly,
        serviceFilter,
        portFilter,
        changedOnly,
        changedPorts,
        sort,
      ],
    );
  const refresh = async () =>
    Promise.all([
      qc.invalidateQueries({ queryKey: ["scans", targetId] }),
      qc.invalidateQueries({ queryKey: ["services", targetId] }),
    ]);
  const upload = async (f: File) => {
    if (!targetId) return;
    const d = new FormData();
    d.append("file", f);
    const r = await fetch(`/api/scans/import/${targetId}`, {
      method: "POST",
      body: d,
    });
    if (!r.ok) throw new Error((await r.json()).detail);
    await refresh();
  };
  const execute = async () => {
    if (!scope) return;
    const r = await fetch("/api/scans/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload()),
    });
    if (!r.ok) {
      setOutput(`[error] ${(await r.json()).detail}\n`);
      setReview(false);
      return;
    }
    const job: Scan = await r.json();
    setReview(false);
    setScanId(job.id);
    setOutput(`$ ${job.command}\n`);
    await refresh();
  };
  const stop = async (id: number) => {
      await fetch(`/api/scans/${id}/stop`, { method: "POST" });
      await refresh();
    },
    rerun = async (id: number) => {
      const r = await fetch(`/api/scans/${id}/rerun`, { method: "POST" });
      if (!r.ok) {
        setOutput(`[error] ${(await r.json()).detail}\n`);
        return;
      }
      const job: Scan = await r.json();
      setScanId(job.id);
      await refresh();
    },
    saveMetadata = async () => {
      if (!selected) return;
      const alias = prompt("Scan alias", selected.alias) || "",
        tags = (
          prompt(
            "Tags (comma separated)",
            JSON.parse(selected.tags || "[]").join(", "),
          ) || ""
        )
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean);
      await fetch(`/api/scans/${selected.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alias, tags }),
      });
      await refresh();
    };
  return (
    <div className="scanPage">
      <header>
        <div className="brand">
          <span className="mark">OW</span>
          <div>
            <b>OSCP Workspace</b>
            <small>Scan Center</small>
          </div>
        </div>
        <div className="scopeNotice">
          OBSERVATIONS ONLY · NO AUTOMATED VULNERABILITY JUDGMENT
        </div>
      </header>
      <nav>
        <a href="#enumeration">Enumeration</a>
        <a href="#web">Web Testing</a>
        <a href="#evidence">Evidence</a>
        <a href="#directory">AD Info</a>
        <a href="#sessions">Sessions</a>
        <a href="#reports">Reports</a>
        <a href="#operations">Operations</a>
        <select
          value={targetId || ""}
          onChange={(e) => {
            setTargetId(+e.target.value);
            setScanId(undefined);
          }}
        >
          <option value="">Choose target</option>
          {targets.data?.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name} · {t.ip}
            </option>
          ))}
        </select>
        <span className="tools">{scans.data?.length || 0} scan records</span>
      </nav>
      <main className="scanLayout">
        <aside className="scanProfiles">
          <div className="panelTitle">
            <span>SCAN PROFILES</span>
            <em>{profiles.data?.length || 0}</em>
          </div>
          {profiles.data?.map((p) => (
            <button
              key={p.id}
              className={p.id === profileId ? "active" : ""}
              onClick={() => setProfileId(p.id)}
            >
              <b>{p.name}</b>
              <small>{p.description}</small>
              <code>{p.arguments}</code>
            </button>
          ))}
        </aside>
        <section className="scanCenter">
          <div className="scanHero">
            <div>
              <span>SCAN CENTER</span>
              <h1>Observed surface, organized.</h1>
              <p>
                Run reviewed Nmap profiles or import XML. Results remain
                factual—no vulnerability scoring or attack selection.
              </p>
            </div>
            <label className="importScan">
              Import XML
              <input
                type="file"
                accept=".xml"
                onChange={(e) =>
                  e.target.files?.[0] && upload(e.target.files[0])
                }
              />
            </label>
          </div>
          <div className="scanComposer">
            {profile?.kind === "selected_ports" && (
              <input
                aria-label="Selected ports"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
              />
            )}
            <code>
              {preview.data?.command || "Choose a target and profile"}
            </code>
            <button
              disabled={!preview.data}
              onClick={() => {
                setScope(false);
                setReview(true);
              }}
            >
              Review scan
            </button>
          </div>
          <div className="scanStats">
            <div>
              <span>SCANS</span>
              <b>{scans.data?.length || 0}</b>
            </div>
            <div>
              <span>OPEN PORTS</span>
              <b>{obs.data?.filter((x) => x.state === "open").length || 0}</b>
            </div>
            <div>
              <span>CHANGED</span>
              <b>{diff.data?.changed.length || 0}</b>
            </div>
          </div>
          <div className="scanFilters">
            <input
              placeholder="Port"
              value={portFilter}
              onChange={(e) => setPortFilter(e.target.value)}
            />
            <input
              placeholder="Service"
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
            />
            <label>
              <input
                type="checkbox"
                checked={openOnly}
                onChange={(e) => setOpenOnly(e.target.checked)}
              />{" "}
              Open only
            </label>
            <label>
              <input
                type="checkbox"
                checked={changedOnly}
                disabled={!diff.data}
                onChange={(e) => setChangedOnly(e.target.checked)}
              />{" "}
              Changed only
            </label>
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as "port" | "service")}
            >
              <option value="port">Sort by port</option>
              <option value="service">Sort by service</option>
            </select>
          </div>
          <div className="scanTable">
            <div className="tableHead">
              <span>PORT</span>
              <span>SERVICE</span>
              <span>PRODUCT / VERSION</span>
              <span>STATE</span>
            </div>
            {visibleObs.map((o) => (
              <div className="tableRow" key={o.id}>
                <b>
                  {o.port}/{o.protocol}
                </b>
                <span>{o.name}</span>
                <span>
                  {[o.product, o.version, o.extra_info]
                    .filter(Boolean)
                    .join(" ") || "—"}
                </span>
                <em>{o.state}</em>
              </div>
            ))}
            {!visibleObs.length && (
              <div className="empty">
                No observations match the current filters.
              </div>
            )}
          </div>
          {scanId && (
            <div className="artifactPanel">
              <div>
                <b>ARTIFACTS</b>
                <button onClick={saveMetadata}>Alias & tags</button>
                <a href={`/api/scans/${scanId}/export?format=csv`}>CSV</a>
                <a href={`/api/scans/${scanId}/export?format=json`}>JSON</a>
              </div>
              {artifacts.data?.map((a) => (
                <a
                  key={a.id}
                  href={`/api/scans/${scanId}/artifacts/${a.id}/download`}
                >
                  <b>{a.kind}</b>
                  <span>
                    {a.original_name} · {bytes(a.size)}
                  </span>
                  <code>{a.sha256}</code>
                </a>
              ))}
            </div>
          )}
          <div className="terminal scanTerminal">
            <div>
              <span />
              <b>SAVED / LIVE OUTPUT</b>
              <small>
                {selected ? `job #${selected.id} · ${selected.status}` : "idle"}
              </small>
            </div>
            <pre>{output}</pre>
          </div>
        </section>
        <aside className="scanHistory">
          <div className="panelTitle">
            <span>SCAN QUEUE & HISTORY</span>
            <em>target</em>
          </div>
          <div className="historyFilters">
            <input
              placeholder="Search scans"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              {[
                "all",
                "queued",
                "running",
                "completed",
                "failed",
                "stopped",
                "interrupted",
              ].map((v) => (
                <option key={v}>{v}</option>
              ))}
            </select>
          </div>
          {visibleScans.map((s) => (
            <button
              key={s.id}
              className={s.id === scanId ? "active" : ""}
              onClick={() => setScanId(s.id)}
            >
              <span>
                <b>{s.alias || `#${s.id}`}</b>
                <em>{s.status}</em>
              </span>
              <small>
                {s.source} · {elapsed(s)} ·{" "}
                {new Date(s.created_at).toLocaleString()}
              </small>
              <code>{s.error || s.command}</code>
              <span className="jobActions">
                {["queued", "running"].includes(s.status) && (
                  <i
                    onClick={(e) => {
                      e.stopPropagation();
                      stop(s.id);
                    }}
                  >
                    Cancel
                  </i>
                )}
                {s.source === "executed" && terminal.includes(s.status) && (
                  <i
                    onClick={(e) => {
                      e.stopPropagation();
                      rerun(s.id);
                    }}
                  >
                    Rerun
                  </i>
                )}
                {s.exit_code != null && <small>exit {s.exit_code}</small>}
              </span>
            </button>
          ))}
          <div className="compare">
            <h3>COMPARE</h3>
            <select
              value={baseId || ""}
              onChange={(e) => setBaseId(+e.target.value)}
            >
              <option value="">Choose baseline</option>
              {scans.data
                ?.filter((s) => s.id !== scanId)
                .map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.alias || `Scan #${s.id}`}
                  </option>
                ))}
            </select>
            {diff.data && (
              <>
                <div className="delta">
                  <span>+{diff.data.added.length}</span>
                  <span>−{diff.data.removed.length}</span>
                  <span>~{diff.data.changed.length}</span>
                </div>
                <a
                  className="diffExport"
                  href={`/api/scans/compare/${baseId}/${scanId}/export`}
                >
                  Export changes
                </a>
                <div className="diffDetails">
                  {diff.data.added.map((item: any) => (
                    <div key={`add-${item.protocol}-${item.port}`}>
                      <b>ADDED {item.port}/{item.protocol}</b>
                      <small>{item.name} {item.product} {item.version}</small>
                    </div>
                  ))}
                  {diff.data.removed.map((item: any) => (
                    <div key={`remove-${item.protocol}-${item.port}`}>
                      <b>REMOVED {item.port}/{item.protocol}</b>
                      <small>{item.name} {item.product} {item.version}</small>
                    </div>
                  ))}
                  {diff.data.changed.map((item: any) => (
                    <div key={`change-${item.protocol}-${item.port}`}>
                      <b>CHANGED {item.port}/{item.protocol}</b>
                      <small>{Object.keys(item.changes).join(", ")}</small>
                    </div>
                  ))}
                </div>
              </>
            )}
            <p>
              Observed changes only; no risk or vulnerability determination.
            </p>
          </div>
        </aside>
      </main>
      {review && (
        <div className="modal">
          <div>
            <span>SCAN SCOPE REVIEW</span>
            <h2>{profile?.name}</h2>
            <p>
              Verify the target and final command. This runs Nmap directly on
              the Kali host.
            </p>
            <code>{preview.data?.command}</code>
            <p>
              <b>Target:</b> {target?.name} · {target?.ip}
            </p>
            <label>
              <input
                type="checkbox"
                checked={scope}
                onChange={(e) => setScope(e.target.checked)}
              />{" "}
              I confirm this target is authorized and in scope.
            </label>
            <footer>
              <button onClick={() => setReview(false)}>Cancel</button>
              <button className="danger" disabled={!scope} onClick={execute}>
                Queue scan
              </button>
            </footer>
          </div>
        </div>
      )}
    </div>
  );
}
