import { parseSecretsdumpHashes } from "./serviceIntel";

export type DomainOpExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};
export type DomainOpRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

const activeOf = (
  runState: DomainOpRunState | undefined, templateId: string,
  serviceExecutions: DomainOpExecution[],
): DomainOpExecution | undefined => {
  if (runState?.templateId === templateId) {
    return { id: runState.id ?? -1, template_id: templateId, status: runState.status,
      stdout: runState.stdout, stderr: runState.stderr };
  }
  return serviceExecutions
    .filter((item) => item.template_id === templateId && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
};

// BloodHound collection and DCSync both need nothing but a working domain
// credential — not a specific service — so, like Kerbrute/AS-REP/spray,
// this lives in its own panel with direct run() calls rather than the
// generic reviewed-command list.
export default function DomainDominancePanel({
  target, domain, username, password, bloodhoundRunState, dcsyncRunState,
  serviceExecutions, evidenceMsg, onCollectBloodhound, onDcsync,
  onCaptureEvidence, onFillCredential, onSaveHash, saveHashMsg,
}: {
  target?: { ip: string };
  domain: string; username: string; password: string;
  bloodhoundRunState?: DomainOpRunState; dcsyncRunState?: DomainOpRunState;
  serviceExecutions: DomainOpExecution[];
  evidenceMsg: string;
  onCollectBloodhound: () => void;
  onDcsync: () => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
  onFillCredential: (username: string, secret: string) => void;
  onSaveHash: (username: string, nthash: string) => void;
  saveHashMsg: string;
}) {
  const bloodhound = activeOf(bloodhoundRunState, "ad-bloodhound-collect", serviceExecutions);
  const dcsync = activeOf(dcsyncRunState, "ad-dcsync-secretsdump", serviceExecutions);
  const bloodhoundBusy = ["starting", "running"].includes(bloodhound?.status || "");
  const dcsyncBusy = ["starting", "running"].includes(dcsync?.status || "");
  const hashes = parseSecretsdumpHashes(dcsync?.stdout || "");
  const ready = !!username.trim() && !!password.trim();

  return (
    <section className="netexecCredCheck" aria-labelledby="domain-dominance-heading">
      <header>
        <h2 id="domain-dominance-heading">도메인 장악 (BloodHound · DCSync)</h2>
        <small>위에서 확인한 유효한 도메인 계정으로 전체 공격 경로 수집과 해시 덤프를 시도합니다.
          DCSync는 복제 권한이 없으면 실패합니다 — 먼저 BloodHound로 경로를 확인하세요.</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <button disabled={!ready || bloodhoundBusy} onClick={onCollectBloodhound}>
          {bloodhoundBusy ? "수집 중…" : "BloodHound 데이터 수집"}
        </button>
        <button disabled={!ready || dcsyncBusy} onClick={onDcsync}>
          {dcsyncBusy ? "시도 중…" : "DCSync 시도"}
        </button>
      </div>
      {bloodhound?.status === "completed" && (
        <p className="netexecEvidenceMsg">
          BloodHound zip이 저장됐습니다. 실행 이력에서 산출물을 내려받아 BloodHound 앱에서 여세요.
          {" "}
          <button onClick={() => onCaptureEvidence(
            bloodhound, `BloodHound 수집 · ${target?.ip}`,
          )}>Evidence로 저장</button>
        </p>
      )}
      {dcsync && (
        <div className="intruderResults">
          <header><div><b>덤프된 계정</b><span>{hashes.length}개</span></div>
            {dcsync.status === "completed" && (
              <button onClick={() => onCaptureEvidence(
                dcsync, `DCSync · ${target?.ip}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {dcsync.status === "completed" && !hashes.length && (
            <p className="empty">덤프된 계정이 없습니다 — DCSync 권한이 없을 수 있습니다.</p>
          )}
          {saveHashMsg && <p className="netexecEvidenceMsg">{saveHashMsg}</p>}
          <ul>{hashes.map((item) => (
            <li key={item.username}>
              <code>{item.username}</code>
              <code title={item.nthash}>{item.nthash}</code>
              <button onClick={() => onFillCredential(item.username, item.nthash)}>
                자격증명 칸에 채우기
              </button>
              <button onClick={() => onSaveHash(item.username, item.nthash)}>
                Credential로 저장
              </button>
            </li>
          ))}</ul>
        </div>
      )}
      {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
    </section>
  );
}
