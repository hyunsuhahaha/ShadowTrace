import { useEffect, useState } from "react";
import { log4shellPayloadCategories } from "./log4shellPayloads";

function randomCanary(): string {
  return Math.random().toString(36).slice(2, 10);
}

// Same shape as SqlPayloadReference/LfiPayloadReference: staging text into
// Intruder's candidate list, never auto-detecting or auto-sending -- a
// scripted scanner like log4j-scan would fan a payload out across every
// header/param on its own and flag whichever one calls back, which is
// exactly the kind of automated exploitation this app avoids. Here the
// user marks the field by hand and reads the listener themselves.
export default function Log4ShellPayloadReference({ onSendToIntruder }: {
  onSendToIntruder?: (payloads: string[]) => void;
}) {
  const [copied, setCopied] = useState<string>();
  const [lhost, setLhost] = useState<string>();
  const [lport, setLport] = useState("1389");
  const [canary, setCanary] = useState(randomCanary);

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

  const resolve = (payload: string) => payload
    .replaceAll("{LHOST}", lhost || "{LHOST}")
    .replaceAll("{LPORT}", lport || "{LPORT}")
    .replaceAll("{CANARY}", canary);

  const copy = async (payload: string) => {
    await navigator.clipboard.writeText(payload);
    setCopied(payload);
    window.setTimeout(() => setCopied((current) =>
      current === payload ? undefined : current), 1500);
  };

  return (
    <div className="sqlPayloadReference" aria-labelledby="log4shell-payload-heading">
      <div className="webSectionTitle">
        <span>Log4Shell (CVE-2021-44228) 페이로드 참고</span>
        <h2 id="log4shell-payload-heading">JNDI 프로브 카탈로그</h2>
        <p>
          {lhost
            ? <>탐지된 tun0 IP <code>{lhost}</code>를 <code>{"{LHOST}"}</code> 자리에 자동으로 채웁니다.</>
            : <>tun0 IP를 아직 못 찾았습니다 — VPN이 연결돼 있는지 확인하거나, <code>{"{LHOST}"}</code>가
              들어간 페이로드는 직접 IP로 바꿔서 사용하세요.</>}
          {" "}로그인 폼의 username/password/remember, User-Agent·X-Forwarded-For·Referer 헤더처럼
          서버가 로그로 남길 만한 입력값에 붙여넣고 콜백을 기다리세요.
        </p>
        <div className="netexecCredForm">
          <input value={lport} onChange={(e) => setLport(e.target.value)}
            placeholder="LPORT" aria-label="LPORT" />
          <input value={canary} readOnly aria-label="CANARY (어느 필드가 트리거됐는지 구분용)" />
          <button type="button" onClick={() => setCanary(randomCanary())}>
            CANARY 새로 생성
          </button>
        </div>
      </div>
      {log4shellPayloadCategories.map((category) => (
        <details key={category.id} className="sqlPayloadCategory">
          <summary>
            <b>{category.title}</b>
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
