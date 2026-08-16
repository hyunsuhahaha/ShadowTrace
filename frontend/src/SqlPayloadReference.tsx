import { useEffect, useState } from "react";
import { sqlPayloadCategories } from "./sqlPayloads";

// Same shape as LfiPayloadReference/Log4ShellPayloadReference: staging text
// into Intruder's candidate list, never auto-detecting or auto-sending — the
// user still marks the injection point, reviews the request count, and
// confirms before anything is sent. See sqlPayloads.ts for why there is no
// automatic detection or exploitation here (SQLmap and similar tools are
// banned on the OSCP exam). {LHOST}/{LPORT} only appear in the postgres
// COPY FROM PROGRAM category's reverse-shell payload -- resolve() is a
// no-op for every other category.
export default function SqlPayloadReference({ onSendToIntruder }: {
  onSendToIntruder?: (payloads: string[]) => void;
}) {
  const [copied, setCopied] = useState<string>();
  const [lhost, setLhost] = useState<string>();
  const [lport, setLport] = useState("4444");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const response = await fetch("/api/vpn/status");
        if (!response.ok || cancelled) return;
        const data = await response.json();
        const match = /(\d{1,3}\.){3}\d{1,3}/.exec(data.tun0 || "");
        if (match && !cancelled) setLhost(match[0]);
      } catch {
        // VPN status is a convenience lookup, not required for the page to work.
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const resolve = (payload: string) => payload
    .replaceAll("{LHOST}", lhost || "{LHOST}")
    .replaceAll("{LPORT}", lport || "{LPORT}");

  const copy = async (payload: string) => {
    await navigator.clipboard.writeText(payload);
    setCopied(payload);
    window.setTimeout(() => setCopied((current) =>
      current === payload ? undefined : current), 1500);
  };
  return (
    <div className="sqlPayloadReference" aria-labelledby="sql-payload-heading">
      <div className="webSectionTitle">
        <span>SQLi 페이로드 참고</span>
        <h2 id="sql-payload-heading">페이로드 카탈로그</h2>
        <p>
          {lhost
            ? <>탐지된 tun0 IP <code>{lhost}</code>를 <code>{"{LHOST}"}</code> 자리에 자동으로 채웁니다.</>
            : <>tun0 IP를 아직 못 찾았습니다 — VPN이 연결돼 있는지 확인하거나, <code>{"{LHOST}"}</code>가
              들어간 페이로드는 직접 IP로 바꿔서 사용하세요.</>}
          {" "}(리버스 쉘 페이로드가 있는 항목에만 해당 — PostgreSQL COPY FROM PROGRAM,
          MSSQL xp_cmdshell, MySQL OUTFILE 웹셸/UDF)
        </p>
        <div className="netexecCredForm">
          <input value={lport} onChange={(e) => setLport(e.target.value)}
            placeholder="LPORT" aria-label="LPORT" />
        </div>
      </div>
      {sqlPayloadCategories.map((category) => (
        <details key={category.id} className="sqlPayloadCategory">
          <summary>
            <b>{category.title}</b>
            <small>{category.engines.join(" · ")}</small>
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
