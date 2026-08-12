import type {RunState} from "./enumerationModel";
import type {ExecutionSummary} from "./serviceIntel";
import {statusCopy as statusLabel} from "./ui";
import {buildFileTree, FileTreeView, parseTaggedTreeLines} from "./fileTree";

// Commands whose captured output is D|/F|-tagged tree lines (see
// backend/app/ftp_tree.py) instead of plain text -- rendered as an
// expandable tree here rather than a raw dump.
const treeTemplateIds = new Set([
  "ftp-directory-tree", "nfs-export-tree", "http-webdav-tree", "git-dump-tree",
  "rsync-module-tree", "imap-mailbox-tree", "redis-key-tree", "mysql-db-tree",
  "svn-dump-recover", "ldap-dit-tree", "mssql-db-tree", "postgres-db-tree",
  "snmp-oid-tree", "mongodb-db-tree", "docker-api-tree",
]);

export default function LiveOutputPanel({run, elapsed, outcome, output, targetIp = "target",
  servicePort, protocol = "tcp"}: {
  run?: RunState; elapsed: number; outcome: ExecutionSummary | null; output: string;
  targetIp?: string; servicePort?: number; protocol?: string;
}) {
  const closed = !!run && !["starting", "running"].includes(run.status);
  return <div className={`terminal terminal--attached${run ? "" : " is-idle"}`}>
    <div className={`terminalStatus${run ? ` terminalStatus--${run.status}` : ""}`}>
      <span className="termDots" aria-hidden="true">
        <i className="termDot" /><i className="termDot termDot--yellow" />
        <i className="termDot termDot--green" />
      </span>
      <div className="attachedTerminal__identity"><b>&gt; service://{targetIp}/{
        servicePort || "-"}/{protocol}/session/{run?.id || "-"}</b>
        <span>{run?.templateId || "awaiting command"}</span></div>
      <small role="status" aria-live="polite">
        {!run
          ? "명령 실행 대기"
          : `${run.name} · ${statusLabel[run.status] ||
            (run.status === "starting" ? "실행 준비 중" : run.status)} · ${elapsed}초${
            run.exitCode == null ? "" : ` · 종료 코드 ${run.exitCode}`
          }`}
      </small>
    </div>
    <div className="attachedTerminal__route"><span>operator@kali</span><b>→</b>
      <span>{protocol}</span><b>→</b><strong>{targetIp}{servicePort ? `:${servicePort}` : ""}</strong>
      <em>{!run ? "AWAITING COMMAND" : closed ? "STREAM CLOSED" : "RX LIVE"}</em></div>
    {run?.message && <p className="terminalError">{run.message}</p>}
    {outcome && (
      <div className={`executionOutcome executionOutcome--${outcome.tone}`}>
        <b>{outcome.title}</b>
        <span>{outcome.detail}</span>
      </div>
    )}
    {run && treeTemplateIds.has(run.templateId) && run.status === "completed" ? (
      <FileTreeView node={buildFileTree(parseTaggedTreeLines(output), "/")} />
    ) : (
      <pre>{output}</pre>
    )}
    <footer className="attachedTerminal__footer"><span>{run ? `EXECUTION #${run.id || "pending"}` : "NO SESSION"}</span>
      <span>{run?.exitCode == null ? "stdout / stderr" : `EXIT ${run.exitCode}`}</span>
      <strong>{run ? (closed ? "CLOSED" : "ATTACHED") : "IDLE"}</strong></footer>
  </div>;
}
