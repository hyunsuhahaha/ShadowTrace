export type ReviewCommand = {
  name: string;
  preview: string;
  risk: string;
};

export default function CommandReviewModal({
  command,
  runWithSudo,
  onSudo,
  outputFilename,
  onOutputFilename,
  onCancel,
  onRun,
}: {
  command?: ReviewCommand;
  runWithSudo: boolean;
  onSudo: (enabled: boolean) => void;
  outputFilename: string;
  onOutputFilename: (value: string) => void;
  onCancel: () => void;
  onRun: () => void;
}) {
  if (!command) return null;
  return <div className="modal" role="presentation">
    <div role="dialog" aria-modal="true" aria-labelledby="command-review-title"
      aria-describedby="command-review-description">
      <span>최종 명령 검토</span>
      <h2 id="command-review-title">{command.name}</h2>
      <p id="command-review-description">
        허가된 대상에서만 실행하세요. 대상과 전체 옵션을 확인한 뒤 실행 버튼을 누르세요.
      </p>
      <code><b style={{ color: "var(--term-cursor)" }}>$</b>{" "}
        {runWithSudo ? `sudo ${command.preview}` : command.preview}</code>
      <label className="sudoOption">
        <input type="checkbox" checked={runWithSudo}
          onChange={(event) => onSudo(event.target.checked)} />
        sudo로 실행
      </label>
      <label className="outputFilenameOption">
        결과 저장 파일명(선택)
        <input type="text" placeholder="예: hello → hello.txt로 저장"
          value={outputFilename}
          onChange={(event) => onOutputFilename(event.target.value)} />
      </label>
      {command.risk === "high" && <p className="intrusiveConfirm">
        이 명령은 계정 잠금이나 인증 로그를 발생시킬 수 있습니다.
      </p>}
      <footer>
        <button onClick={onCancel}>취소</button>
        <button className="danger" onClick={onRun}>명령 실행</button>
      </footer>
    </div>
  </div>;
}
