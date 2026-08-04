import { useState } from "react";

export type S3PanelExecution = {
  id: number; template_id: string; status: string;
  stdout?: string; stderr?: string;
};
export type S3PanelRunState = {
  id?: number; templateId: string; status: string; stdout?: string; stderr?: string;
};

function actionState(
  templateId: string, runState: S3PanelRunState | undefined,
  serviceExecutions: S3PanelExecution[],
) {
  const active = runState?.templateId === templateId ? runState : undefined;
  const latest = serviceExecutions
    .filter((item) => item.template_id === templateId && item.status === "completed")
    .sort((a, b) => b.id - a.id)[0];
  const output = active?.stdout || latest?.stdout || "";
  const busy = !!active && ["starting", "running"].includes(active.status);
  const executionForEvidence = active?.id
    ? { id: active.id, stdout: active.stdout, stderr: active.stderr }
    : latest
      ? { id: latest.id, stdout: latest.stdout, stderr: latest.stderr }
      : undefined;
  return { output, busy, executionForEvidence };
}

// S3-compatible endpoints (MinIO etc.) sit next to the regular HTTP surface
// but need awscli rather than curl/ffuf, so — like the fuzzing panels next
// to it — this lives on its own with direct run() calls per action.
export default function S3BucketPanel({
  target, bucketRunState, objectRunState, serviceExecutions, evidenceMsg,
  onListBuckets, onListObjects, onCaptureEvidence,
}: {
  target?: { ip: string };
  bucketRunState?: S3PanelRunState;
  objectRunState?: S3PanelRunState;
  serviceExecutions: S3PanelExecution[];
  evidenceMsg: string;
  onListBuckets: () => void;
  onListObjects: (bucket: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [bucket, setBucket] = useState("");
  const bucketList = actionState("s3-bucket-list", bucketRunState, serviceExecutions);
  const objectList = actionState("s3-object-list", objectRunState, serviceExecutions);

  return (
    <section className="netexecCredCheck" aria-labelledby="s3-heading">
      <header>
        <h2 id="s3-heading">S3 호환 버킷 확인 (awscli)</h2>
        <small>커스텀 S3 호환 엔드포인트(MinIO 등)의 버킷과 오브젝트를 열거합니다.
          awscli에 자격증명(더미 값이라도 무방)이 미리 구성돼 있어야 합니다.</small>
      </header>
      <div className="netexecCredForm netexecCredForm--save">
        <button disabled={bucketList.busy} onClick={onListBuckets}>
          {bucketList.busy ? "조회 중…" : "버킷 목록 조회"}
        </button>
      </div>
      {!!bucketList.output && (
        <div className="intruderResults">
          <header><div><b>버킷 목록</b></div>
            {bucketList.executionForEvidence && (
              <button onClick={() => onCaptureEvidence(
                bucketList.executionForEvidence!, `S3 버킷 목록 · ${target?.ip}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          {evidenceMsg && <p className="netexecEvidenceMsg">{evidenceMsg}</p>}
          <pre>{bucketList.output}</pre>
        </div>
      )}
      <div className="netexecCredForm netexecCredForm--save">
        <input value={bucket} onChange={(e) => setBucket(e.target.value)}
          placeholder="버킷 이름 (예: the-three.htb)" aria-label="버킷 이름" />
        <button disabled={objectList.busy || !bucket.trim()}
          onClick={() => onListObjects(bucket.trim())}>
          {objectList.busy ? "조회 중…" : "버킷 파일 목록 조회"}
        </button>
      </div>
      {!!objectList.output && (
        <div className="intruderResults">
          <header><div><b>버킷 파일 목록</b></div>
            {objectList.executionForEvidence && (
              <button onClick={() => onCaptureEvidence(
                objectList.executionForEvidence!, `S3 버킷 파일 목록 · ${bucket}`,
              )}>Evidence로 저장</button>
            )}
          </header>
          <pre>{objectList.output}</pre>
        </div>
      )}
    </section>
  );
}
