export type ScanTool = "nmap" | "masscan" | "autorecon";

export default function ScanToolPicker({tool, masscanBlockedByVpn, onSelect}: {
  tool: ScanTool; masscanBlockedByVpn: boolean;
  onSelect: (tool: ScanTool) => void;
}) {
  return <aside className="scanProfiles">
    <div className="panelTitle">
      <span className="panelTitle__label">
        <span className="termDots" aria-hidden="true">
          <i className="termDot" /><i className="termDot termDot--yellow" />
          <i className="termDot termDot--green" />
        </span>
        도구 선택
      </span>
    </div>
    <button
      type="button"
      className={`toolRow ${tool === "nmap" ? "active" : ""}`}
      onClick={() => onSelect("nmap")}
    >
      <em aria-hidden="true">{tool === "nmap" ? ">" : " "}</em>
      <span>
        <b>nmap</b>
        <small>포트 및 서비스 상세 스캔</small>
      </span>
    </button>
    <button
      type="button"
      className={`toolRow ${tool === "masscan" ? "active" : ""}`}
      disabled={masscanBlockedByVpn}
      title={
        masscanBlockedByVpn
          ? "tun0(VPN) 인터페이스는 이더넷/ARP 계층이 없어 masscan이 패킷을 보낼 수 없습니다. VPN 연결을 끊으면 사용할 수 있습니다."
          : undefined
      }
      onClick={() => onSelect("masscan")}
    >
      <em aria-hidden="true">{tool === "masscan" ? ">" : " "}</em>
      <span>
        <b>masscan</b>
        <small>
          {masscanBlockedByVpn
            ? "tun0(VPN)에서는 사용할 수 없음"
            : "초고속 포트 탐색 · 자동 Nmap 상세 스캔 연계"}
        </small>
      </span>
    </button>
    <button type="button"
      className={`toolRow ${tool === "autorecon" ? "active" : ""}`}
      onClick={() => onSelect("autorecon")}
    >
      <em aria-hidden="true">{tool === "autorecon" ? ">" : " "}</em>
      <span>
        <b>autorecon</b>
        <small>여러 대상 동시 정찰 및 서비스별 자동 열거</small>
      </span>
    </button>
  </aside>;
}
