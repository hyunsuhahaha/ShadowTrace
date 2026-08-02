export default function ScanToolPicker({tool, masscanBlockedByVpn, onSelect}: {
  tool: "nmap" | "masscan"; masscanBlockedByVpn: boolean;
  onSelect: (tool: "nmap" | "masscan") => void;
}) {
  return <aside className="scanProfiles">
    <div className="panelTitle">
      <span>스캔 도구</span>
    </div>
    <button
      type="button"
      className={tool === "nmap" ? "active" : ""}
      onClick={() => onSelect("nmap")}
    >
      <b>Nmap</b>
      <small>포트 및 서비스 상세 스캔</small>
    </button>
    <button
      type="button"
      className={tool === "masscan" ? "active" : ""}
      disabled={masscanBlockedByVpn}
      title={
        masscanBlockedByVpn
          ? "tun0(VPN) 인터페이스는 이더넷/ARP 계층이 없어 masscan이 패킷을 보낼 수 없습니다. VPN 연결을 끊으면 사용할 수 있습니다."
          : undefined
      }
      onClick={() => onSelect("masscan")}
    >
      <b>masscan</b>
      <small>
        {masscanBlockedByVpn
          ? "tun0(VPN)에서는 사용할 수 없음"
          : "초고속 포트 탐색 · 자동 Nmap 상세 스캔 연계"}
      </small>
    </button>
  </aside>;
}
