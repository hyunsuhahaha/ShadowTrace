import { useState } from "react";
import { windowsPrivescCategories } from "./windowsPrivescCommands";

// Mirrors LinuxPrivescReference.tsx exactly -- same copy-only, no-auto-exec
// shape as SqlPayloadReference/LfiPayloadReference. When onSendCommand is
// given, "셸에 입력" types the command into the attached PTY for the
// operator to review and press Enter themselves -- it never submits on its
// own.
export default function WindowsPrivescReference({ onSendCommand }: {
  onSendCommand?: (command: string) => void;
}) {
  const [copied, setCopied] = useState<string>();

  const copy = async (command: string) => {
    await navigator.clipboard.writeText(command);
    setCopied(command);
    window.setTimeout(() => setCopied((current) =>
      current === command ? undefined : current), 1500);
  };

  return (
    <div className="sqlPayloadReference" aria-labelledby="windows-privesc-heading">
      <div className="webSectionTitle">
        <span>Windows PrivEsc 참고</span>
        <h2 id="windows-privesc-heading">권한 상승 체크리스트</h2>
        <p>
          WinPEAS 자동 스캔과 별개로, 어디부터 손으로 훑어야 할지 감이 안 잡힐 때 쓰는 참고
          목록입니다. PowerShell 히스토리·서비스 권한처럼 흔한 경로부터 정리돼 있습니다.
        </p>
      </div>
      {windowsPrivescCategories.map((category) => (
        <details key={category.id} id={`winprivesc-${category.id}`} className="sqlPayloadCategory">
          <summary>
            <b>{category.title}</b>
          </summary>
          <p>{category.description}</p>
          <div className="sqlPayloadList">
            {category.commands.map((item) => (
              <div key={item.label} className="sqlPayloadRow">
                <div>
                  <b>{item.label}</b>
                  <code>{item.command}</code>
                  {item.note && <small>{item.note}</small>}
                </div>
                <div className="sqlPayloadActions">
                  <button onClick={() => void copy(item.command)}>
                    {copied === item.command ? "복사됨" : "복사"}
                  </button>
                  {onSendCommand && <button onClick={() => onSendCommand(item.command)}>
                    셸에 입력
                  </button>}
                </div>
              </div>
            ))}
          </div>
        </details>
      ))}
    </div>
  );
}
