import {useEffect, useMemo, useState} from "react";
import SqlPayloadReference from "./SqlPayloadReference";
import {dbPayloadCategoriesFor} from "./sqlPayloads";

export type ServiceCommand = {
  id: string;
  name: string;
  description?: string;
  preview: string;
  command: string;
  tool?: string;
  risk: "low" | "medium" | "high";
  execution_mode: "captured" | "interactive";
  sudo?: boolean;
  target_level?: boolean;
  variables?: Record<string, string>;
  command_override?: string;
};

const tokenPattern = /\{([a-z_]+)\}/g;
const sensitiveTokens = new Set(["password", "nthash"]);
const quote = (value: string) => `'${value.replace(/'/g, "'\\''")}'`;
const engine = (command: string) => {
  const words = command.trim().split(/\s+/);
  return words[0] === "sudo" ? words[1] : words[0];
};
const boundCount = (command: string, value: string, numeric = false) => {
  if (!value) return 0;
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return command.match(new RegExp(
    numeric ? `(^|\\D)${escaped}(?!\\d)` : escaped, "g"))?.length || 0;
};
const renderVariables = (command: string, values: Record<string, string>) =>
  command.replace(tokenPattern, (token, name) => values[name] == null || values[name] === ""
    ? token : quote(values[name]));

export function commandBinding(base: string, draft: string, host: string, port: number,
  alternateHost = "") {
  return {
    engine: engine(base) === engine(draft),
    target: boundCount(draft, host) >= boundCount(base, host)
      && boundCount(draft, alternateHost) >= boundCount(base, alternateHost),
    service: boundCount(draft, String(port), true) >= boundCount(base, String(port), true),
  };
}

export default function ServiceCommandSession({commands, serviceKey, targetIp,
  targetHostname, port, protocol, serviceName, credentials, onReview}: {
  commands: ServiceCommand[];
  serviceKey: string;
  targetIp: string;
  targetHostname?: string;
  port: number;
  protocol: string;
  // nmap's own service-detection name (postgresql/mysql/ms-sql-s/...) --
  // only used to look up a matching DB payload reference (recon/basics +
  // RCE; see the collapsed section below), same string services.yaml's
  // `database:` match uses.
  serviceName?: string;
  // Known project credentials (Credential Store) offered as one-click
  // username fills for whichever interactive client profile this service
  // matched (ssh-client, etc.) -- password stays untouched, since these
  // clients all prompt for it interactively themselves; see the quick-connect
  // callout below.
  credentials?: {username: string}[];
  onReview: (command: ServiceCommand) => void;
}) {
  const [selectedId, setSelectedId] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const selected = commands.find((item) => item.id === selectedId) || commands[0];
  const renderedBase = useMemo(() => selected
    ? renderVariables(selected.preview, values) : "", [selected, values]);
  const [draft, setDraft] = useState("");
  const [edited, setEdited] = useState(false);
  const dirty = !!selected && edited;

  useEffect(() => {
    const first = commands[0];
    setSelectedId(first?.id || "");
    setValues({});
    setDraft(first?.preview || "");
    setEdited(false);
  }, [serviceKey, commands]);
  useEffect(() => {
    if (!edited) setDraft(renderedBase);
  }, [edited, renderedBase]);

  if (!selected) return <section className="serviceCommandSession is-empty">
    <p>$ no command profile matched this service</p>
  </section>;

  const required = [...new Set(Array.from(renderedBase.matchAll(tokenPattern), (match) => match[1]))];
  const editableRequired = required.filter((name) => !sensitiveTokens.has(name));
  const credentialRequired = required.filter((name) => sensitiveTokens.has(name));
  const binding = commandBinding(renderedBase, draft, targetIp, port, targetHostname);
  const canRun = !required.length && binding.engine && binding.target && binding.service;
  const stage = () => canRun && onReview({
    ...selected,
    preview: draft.trim(),
    variables: values,
    command_override: dirty ? draft.trim() : undefined,
  });
  const select = (id: string) => {
    const command = commands.find((item) => item.id === id);
    setSelectedId(id);
    setDraft(command?.preview || "");
    setEdited(false);
  };
  // Any interactive client profile the catalog matched for this service that
  // only needs a username (ssh-client, etc.) -- the client itself prompts
  // for the password interactively, so quick-filling just the username is
  // enough to get to a ready-to-review connection attempt.
  const quickConnectProfile = commands.find((item) =>
    item.execution_mode === "interactive" && /\{username\}/.test(item.preview)
    && !/\{password\}/.test(item.preview));
  const knownUsernames = quickConnectProfile && credentials
    ? [...new Set(credentials.map((item) => item.username).filter(Boolean))] : [];
  const quickConnect = (username: string) => {
    if (!quickConnectProfile) return;
    select(quickConnectProfile.id);
    setValues((current) => ({...current, username}));
  };
  const dbPayloadCategories = serviceName ? dbPayloadCategoriesFor(serviceName) : [];

  return <section className="serviceCommandSession" aria-label="서비스 명령 세션">
    <header>
      <div><small>SERVICE COMMAND</small><strong>{selected.name}</strong></div>
      <span>{selected.execution_mode === "interactive" ? "PTY" : "STDOUT"}</span>
    </header>
    {!!knownUsernames.length && <div className="webServiceActions">
      <span>알려진 계정으로 접속 시도</span>
      {knownUsernames.map((username) => <button key={username} type="button"
        onClick={() => quickConnect(username)}>
        {username} · {quickConnectProfile!.name}
      </button>)}
    </div>}
    <label className="serviceCommandSession__profile">
      <span>PROFILE</span>
      <select aria-label="서비스 명령 프로필" value={selected.id}
        onChange={(event) => select(event.target.value)}>
        {commands.map((command) => <option key={command.id} value={command.id}>
          {command.name}
        </option>)}
      </select>
    </label>
    {!!editableRequired.length && <div className="serviceCommandSession__variables">
      {editableRequired.map((name) => <label key={name}><span>{name.toUpperCase()}</span>
        <input value={values[name] || ""} autoComplete="off"
          aria-label={`${name} 컨텍스트`}
          onChange={(event) => setValues((current) => ({
            ...current, [name]: event.target.value,
          }))} /></label>)}
    </div>}
    <div className="serviceCommandSession__repl">
      <div><span>REPL / EDITABLE ARGV</span>
        <small>{dirty ? "operator modified" : "profile rendered"}</small></div>
      <label><b>$</b><textarea aria-label="서비스 명령" rows={3} spellCheck={false}
        value={draft} onChange={(event) => {
          setDraft(event.target.value);
          setEdited(event.target.value.trim() !== renderedBase.trim());
        }}
        onKeyDown={(event) => {
          if ((event.ctrlKey || event.metaKey) && event.key === "Enter") stage();
        }} /></label>
      {(dirty || !canRun) && <div className="serviceCommandSession__state" aria-live="polite">
        {dirty && <span className="is-modified">OPERATOR EDIT</span>}
        {!!editableRequired.length && <span className="is-pending">
          CONTEXT REQUIRED · {editableRequired.join(" / ")}</span>}
        {!!credentialRequired.length && <span className="is-pending">
          CREDENTIAL CONTEXT · USE PROTOCOL TOOLBOX</span>}
        {!binding.target && <span className="is-drift">TARGET CHANGED · EXECUTION LOCKED</span>}
        {!binding.service && <span className="is-drift">SERVICE CHANGED · EXECUTION LOCKED</span>}
        {!binding.engine && <span className="is-drift">ENGINE CHANGED · EXECUTION LOCKED</span>}
        {dirty && <button type="button" onClick={() => {
          setDraft(renderedBase); setEdited(false);
        }}>RESTORE PROFILE</button>}
      </div>}
    </div>
    <footer><p># {selected.description || `${port}/${protocol} 컨텍스트에 바인딩된 명령`}</p>
      <button type="button" disabled={!canRun} onClick={stage}>[ RUN ↵ ]</button></footer>
    {!!dbPayloadCategories.length && <details className="sqlPayloadCategory">
      <summary><b>DB 페이로드 참고 열기</b></summary>
      <SqlPayloadReference categories={dbPayloadCategories} />
    </details>}
  </section>;
}
