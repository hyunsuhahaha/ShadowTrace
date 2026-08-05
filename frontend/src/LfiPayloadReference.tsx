import { useEffect, useState } from "react";
import { lfiPayloadCategories } from "./lfiPayloads";

// Same shape as SqlPayloadReference: staging text into Intruder's candidate
// list, never auto-detecting or auto-sending. Traversal depth and target
// file are independent axes, so categories are meant to be combined by hand
// (find the depth first, then swap in a target file) rather than run as one
// giant combined wordlist.
export default function LfiPayloadReference({ onSendToIntruder }: {
  onSendToIntruder?: (payloads: string[]) => void;
}) {
  const [copied, setCopied] = useState<string>();
  const [lhost, setLhost] = useState<string>();
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const response = await fetch("/api/vpn/status");
      if (!response.ok || cancelled) return;
      const data = await response.json();
      const match = /(\d{1,3}\.){3}\d{1,3}/.exec(data.tun0 || "");
      if (match && !cancelled) setLhost(match[0]);
    })();
    return () => { cancelled = true; };
  }, []);
  const resolve = (payload: string) =>
    payload.includes("{LHOST}") && lhost ? payload.replaceAll("{LHOST}", lhost) : payload;
  const copy = async (payload: string) => {
    await navigator.clipboard.writeText(payload);
    setCopied(payload);
    window.setTimeout(() => setCopied((current) =>
      current === payload ? undefined : current), 1500);
  };
  return (
    <div className="sqlPayloadReference" aria-labelledby="lfi-payload-heading">
      <div className="webSectionTitle">
        <span>LFI 페이로드 참고</span>
        <h2 id="lfi-payload-heading">페이로드 카탈로그</h2>
        <p>
          {lhost
            ? <>탐지된 tun0 IP <code>{lhost}</code>를 <code>{"{LHOST}"}</code> 자리에 자동으로 채웁니다.</>
            : <>tun0 IP를 아직 못 찾았습니다 — VPN이 연결돼 있는지 확인하거나, <code>{"{LHOST}"}</code>가
              들어간 페이로드는 직접 IP로 바꿔서 사용하세요.</>}
        </p>
      </div>
      {lfiPayloadCategories.map((category) => (
        <details key={category.id} className="sqlPayloadCategory">
          <summary>
            <b>{category.title}</b>
            <small>{category.targets.join(" · ")}</small>
          </summary>
          <p>{category.description}</p>
          {onSendToIntruder && <button type="button" className="sqlPayloadCategorySend"
            onClick={() => onSendToIntruder(category.payloads.map((item) => resolve(item.payload)))}>
            카테고리 전체를 Intruder 후보로 보내기 →
          </button>}
          <div className="sqlPayloadList">
            {category.payloads.map((item) => (
              <div key={item.label} className="sqlPayloadRow">
                <div>
                  <b>{item.label}</b>
                  <code>{resolve(item.payload)}</code>
                  {item.note && <small>{item.note}</small>}
                </div>
                <div className="sqlPayloadActions">
                  <button onClick={() => void copy(resolve(item.payload))}>
                    {copied === resolve(item.payload) ? "복사됨" : "복사"}
                  </button>
                  {onSendToIntruder && <button onClick={() => onSendToIntruder([resolve(item.payload)])}>
                    Intruder로
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
