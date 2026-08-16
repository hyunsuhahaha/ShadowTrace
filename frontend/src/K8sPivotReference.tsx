import { useState } from "react";
import { k8sPivotCategories } from "./k8sPivotCommands";

// Mirrors McpExploitReference.tsx exactly -- copy-only, no-auto-exec. This
// runs from a shell already inside a pod (e.g. the mcp-user shell from the
// MCP RCE step), using that pod's own mounted service-account token.
export default function K8sPivotReference({ onSendCommand }: {
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
    <div className="sqlPayloadReference" aria-labelledby="k8s-pivot-heading">
      <div className="webSectionTitle">
        <span>Kubernetes 파드 피벗 참고</span>
        <h2 id="k8s-pivot-heading">kubelet 피벗 체크리스트</h2>
        <p>
          파드 안 셸에서 RBAC 자기 권한을 확인하고, hostPath로 호스트 파일시스템을 마운트한
          특권 파드를 찾은 뒤 kubelet exec API로 그 파드에 들어가는 순서입니다.
        </p>
      </div>
      {k8sPivotCategories.map((category) => (
        <details key={category.id} id={`k8s-${category.id}`} className="sqlPayloadCategory">
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
