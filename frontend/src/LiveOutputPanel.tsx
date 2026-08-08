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
]);

export default function LiveOutputPanel({run, elapsed, outcome, output}: {
  run?: RunState; elapsed: number; outcome: ExecutionSummary | null; output: string;
}) {
  return <div className="terminal">
    <div className={`terminalStatus${run ? ` terminalStatus--${run.status}` : ""}`}>
      <span aria-hidden="true" />
      <b>실시간 출력</b>
      <small role="status" aria-live="polite">
        {!run
          ? "명령 실행 대기"
          : `${run.name} · ${statusLabel[run.status] ||
            (run.status === "starting" ? "실행 준비 중" : run.status)} · ${elapsed}초${
            run.exitCode == null ? "" : ` · 종료 코드 ${run.exitCode}`
          }`}
      </small>
    </div>
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
  </div>;
}
