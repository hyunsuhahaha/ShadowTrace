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
  targetLabel = "selected target",
  routeLabel = "kali / local",
  onCancel,
  onRun,
}: {
  command?: ReviewCommand;
  runWithSudo: boolean;
  onSudo: (enabled: boolean) => void;
  outputFilename: string;
  onOutputFilename: (value: string) => void;
  targetLabel?: string;
  routeLabel?: string;
  onCancel: () => void;
  onRun: () => void;
}) {
  if (!command) return null;
  const renderedCommand = runWithSudo ? `sudo ${command.preview}` : command.preview;
  return <div className="modal executionReviewOverlay" role="presentation">
    <div className="executionReview" role="dialog" aria-modal="true"
      aria-labelledby="command-review-title" aria-describedby="command-review-description"
      onKeyDown={(event) => {
        if (event.key === "Escape") onCancel();
        if ((event.ctrlKey || event.metaKey) && event.key === "Enter") onRun();
      }}>
      <header className="executionReview__bar">
        <span className="termDots" aria-hidden="true">
          <i className="termDot" /><i className="termDot termDot--yellow" />
          <i className="termDot termDot--green" />
        </span>
        <code>ow://execution/stage</code>
        <strong><i /> STAGED</strong>
      </header>
      <div className="executionReview__body">
        <div className="executionReview__intro">
          <span>COMMAND REVIEW · {command.risk.toUpperCase()} RISK</span>
          <h2 id="command-review-title">{command.name}</h2>
          <p id="command-review-description">
            # 허가된 대상과 전체 옵션을 확인한 뒤 명령을 전송하세요.
          </p>
        </div>
        <div className="executionRoute" aria-label={`실행 경로: operator, ${routeLabel}, ${targetLabel}`}>
          <span>operator</span><b>→</b><span>{routeLabel}</span><b>→</b><strong>{targetLabel}</strong>
          <i aria-hidden="true" />
        </div>
        <section className="executionCommand" aria-label="실행할 명령">
          <header><span>ARGV / RENDERED</span><small>awaiting operator approval</small></header>
          <code><b>$</b> {renderedCommand}<i aria-hidden="true" /></code>
        </section>
        <dl className="executionFacts">
          <div><dt>scope</dt><dd>operator approved</dd></div>
          <div><dt>privilege</dt><dd>{runWithSudo ? "sudo" : "user"}</dd></div>
          <div><dt>output</dt><dd>{outputFilename || "live stream"}</dd></div>
        </dl>
        <div className="executionReview__controls">
          <label className="sudoOption">
            <input type="checkbox" checked={runWithSudo} autoFocus
              onChange={(event) => onSudo(event.target.checked)} />
            <span>sudo로 실행</span>
          </label>
          <label className="outputFilenameOption">
            <span>결과 저장 파일명 <small>optional</small></span>
            <input type="text" placeholder="예: hello → hello.txt로 저장"
              value={outputFilename}
              onChange={(event) => onOutputFilename(event.target.value)} />
          </label>
        </div>
        {command.risk === "high" && <p className="executionAlert" role="alert">
          <b>INTRUSIVE</b> 계정 잠금이나 인증 로그를 발생시킬 수 있습니다.
        </p>}
      </div>
      <footer className="executionReview__footer">
        <small><kbd>esc</kbd> cancel · <kbd>ctrl</kbd> + <kbd>↵</kbd> execute</small>
        <div><button onClick={onCancel}>취소</button>
          <button className="executionReview__execute" onClick={onRun}>[ EXECUTE ↵ ]</button></div>
      </footer>
    </div>
  </div>;
}
