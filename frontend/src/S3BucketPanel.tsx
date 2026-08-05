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
  target, bucketRunState, objectRunState, uploadRunState, serviceExecutions, evidenceMsg,
  onListBuckets, onListObjects, onUploadWebshell, onCaptureEvidence,
}: {
  target?: { ip: string };
  bucketRunState?: S3PanelRunState;
  objectRunState?: S3PanelRunState;
  uploadRunState?: S3PanelRunState;
  serviceExecutions: S3PanelExecution[];
  evidenceMsg: string;
  onListBuckets: () => void;
  onListObjects: (bucket: string) => void;
  onUploadWebshell: (bucket: string) => void;
  onCaptureEvidence: (
    execution: { id: number; stdout?: string; stderr?: string }, title: string,
  ) => void;
}) {
  const [bucket, setBucket] = useState("");
  const bucketList = actionState("s3-bucket-list", bucketRunState, serviceExecutions);
  const objectList = actionState("s3-object-list", objectRunState, serviceExecutions);
  const upload = actionState("s3-webshell-upload", uploadRunState, serviceExecutions);

  return (
    <section className="netexecCredCheck" aria-labelledby="s3-heading">
      <header>
        <h2 id="s3-heading">S3 호환 버킷 확인 (awscli)</h2>
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
        <button disabled={upload.busy || !bucket.trim()}
          onClick={() => onUploadWebshell(bucket.trim())}>
          {upload.busy ? "업로드 중…" : "PHP 웹쉘 업로드"}
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
      {!!upload.output && (
        <div className="intruderResults">
          <header><div><b>웹쉘 업로드 결과</b></div>
            {upload.executionForEvidence && (
              <button onClick={() => onCaptureEvidence(
                upload.executionForEvidence!, `S3 웹쉘 업로드 · ${bucket}/shell.php`,
              )}>Evidence로 저장</button>
            )}
          </header>
          <pre>{upload.output}</pre>
        </div>
      )}
    </section>
  );
}
