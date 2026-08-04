import { useState } from "react";

export type CloudEnumExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};
export type CloudEnumRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

// cloud_enum hits the real AWS/Azure/GCP endpoints directly from a naming
// keyword, not the target's IP/port, so — like vhost fuzzing next to it —
// this lives in its own panel with a direct run() call.
export default function CloudEnumPanel({
  target, runState, serviceExecutions, evidenceMsg, onEnum, onCaptureEvidence,
}: {
  target?: { ip: string };
  runState?: CloudEnumRunState;
  serviceExecutions: CloudEnumExecution[];
  evidenceMsg: string;
  onEnum: (keyword: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [keyword, setKeyword] = useState("");
  const enumRunState = runState?.templateId === "cloud-enum-bucket-discovery" ? runState : undefined;
  const latestEnum = serviceExecutions
    .filter((item) => item.template_id === "cloud-enum-bucket-discovery" && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const output = enumRunState?.stdout || latestEnum?.stdout || "";
  const busy = !!enumRunState && ["starting", "running"].includes(enumRunState.status);
  const activeExecution = enumRunState?.id
    ? { id: enumRunState.id, stdout: enumRunState.stdout, stderr: enumRunState.stderr }
    : latestEnum
      ? { id: latestEnum.id, stdout: latestEnum.stdout, stderr: latestEnum.stderr }
      : undefined;

  return (
    <section className="netexecCredCheck" aria-labelledby="cloud-enum-heading">
      <header>
        <h2 id="cloud-enum-heading">클라우드 버킷 이름 탐색 (cloud_enum)</h2>
        <small>키워드(회사·프로젝트명 등)로 실제 AWS S3·Azure Blob·GCS 엔드포인트에 존재하는
          버킷·스토리지 계정을 조회합니다. 대상 IP가 아니라 각 클라우드 사업자의 실제 서비스로
          직접 요청이 나가므로, 계약 범위에 해당 키워드 조사가 포함되는지 먼저 확인하세요.</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <input value={keyword} onChange={(e) => setKeyword(e.target.value)}
          placeholder="키워드 (예: the-three)" aria-label="키워드" />
        <button disabled={busy || !keyword.trim()} onClick={() => onEnum(keyword.trim())}>
          {busy ? "탐색 중…" : "탐색 시작"}
        </button>
      </div>
      {!!output && (
        <div className="intruderResults">
          <header><div><b>결과</b></div>
            {activeExecution && (
              <button onClick={() => onCaptureEvidence(
                activeExecution, `클라우드 버킷 탐색 · ${keyword || target?.ip}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <pre>{output}</pre>
        </div>
      )}
    </section>
  );
}
