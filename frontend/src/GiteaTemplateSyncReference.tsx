import { useState } from "react";
import { giteaTemplateSyncCategories } from "./giteaTemplateSyncCommands";

// Mirrors McpExploitReference.tsx/K8sPivotReference.tsx exactly -- copy-only,
// no-auto-exec. Runs from a shell already on the box (Gitea's API is usually
// bound to localhost, unreachable from the graph's own HTTP request panel).
export default function GiteaTemplateSyncReference({ onSendCommand }: {
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
    <div className="sqlPayloadReference" aria-labelledby="gitea-template-sync-heading">
      <div className="webSectionTitle">
        <span>Gitea template 동기화 path traversal 참고</span>
        <h2 id="gitea-template-sync-heading">Gitea → root 체크리스트</h2>
        <p>
          root 소유 동기화 타이머가 Gitea의 "template" 레포를 git ls-tree로 훑어 경로 검증 없이
          파일을 씁니다 -- 이 순서대로 진행하세요.
        </p>
      </div>
      {giteaTemplateSyncCategories.map((category) => (
        <details key={category.id} id={`gitea-${category.id}`} className="sqlPayloadCategory">
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
