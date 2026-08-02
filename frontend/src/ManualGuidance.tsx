import {authContextNotice} from "./enumerationModel";
import type {ServiceGuidance} from "./serviceGuidance";

export default function ManualGuidance({serviceName, guidance}: {
  serviceName?: string;
  guidance: ServiceGuidance | null;
}) {
  const notice = serviceName ? authContextNotice[serviceName] : undefined;
  return <>
    {notice && <div className="identityNotice" role="note">
      <b>이 프로토콜은 추가 인증 문맥이 필요합니다</b><p>{notice}</p>
    </div>}
    {guidance && <section className="manualGuidance"
      aria-labelledby="manual-guidance-title">
      <div><span>수동 상호작용 안내</span>
        <h2 id="manual-guidance-title">{guidance.title}</h2>
        <p>대화형 명령은 Kali의 실제 데스크톱 터미널에서 실행됩니다.
          계정 후보는 복사한 뒤 터미널에서 직접 입력하세요.</p>
      </div>
      <code>{guidance.command}</code>
      <button onClick={() => navigator.clipboard.writeText(guidance.command)}>
        접속 명령 복사
      </button>
      <ol>{guidance.steps.map((step) => <li key={step}>{step}</li>)}</ol>
      <div className="accountCandidates" aria-label="정적 계정 후보">
        <b>로그인 계정 입력</b>
        {guidance.accountCandidates.map((account) => <button key={account}
          onClick={() => navigator.clipboard.writeText(account)}>{account} 복사</button>)}
      </div>
      {!!guidance.verificationCommands?.length && <div className="verificationCommands">
        <b>로그인 후 버전 확인 명령</b>
        <p>대상 셸에 로그인한 뒤 운영체제에 맞는 명령 하나를 직접 실행하세요.</p>
        {guidance.verificationCommands.map((command) => <div key={command}>
          <code>{command}</code><button
            onClick={() => navigator.clipboard.writeText(command)}>복사</button>
        </div>)}
      </div>}
    </section>}
  </>;
}
