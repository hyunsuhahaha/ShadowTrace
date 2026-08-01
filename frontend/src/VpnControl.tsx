import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

const api = async (path: string, init?: RequestInit) => {
  const response = await fetch("/api" + path, init);
  if (!response.ok) {
    const data = await response.json();
    throw new Error(data.detail || response.statusText);
  }
  return response.json();
};

export default function VpnControl() {
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [prepared, setPrepared] = useState<any>();
  const status = useQuery({
    queryKey: ["vpnStatus"],
    queryFn: () => api("/vpn/status"),
    refetchInterval: 3000,
    refetchIntervalInBackground: true,
    refetchOnWindowFocus: "always",
  });
  const vpn = status.data;

  const prepare = async (file: File) => {
    setBusy(true);
    setError("");
    const data = new FormData();
    data.append("file", file);
    try {
      setPrepared(await api("/vpn/prepare", { method: "POST", body: data }));
    } catch (reason) {
      setError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  };
  const connect = async () => {
    if (!prepared) return;
    setBusy(true);
    setError("");
    try {
      const connected = await api("/vpn/connect", {
        method: "POST", headers: {"Content-Type": "application/json"},
        body: JSON.stringify({approval_token: prepared.approval_token}),
      });
      queryClient.setQueryData(["vpnStatus"], connected);
      setPrepared(undefined);
      await queryClient.invalidateQueries({ queryKey: ["vpnStatus"] });
      await queryClient.invalidateQueries({ queryKey: ["status"] });
    } catch (reason) {
      setPrepared(undefined);
      setError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  };

  const disconnect = async () => {
    setBusy(true);
    setError("");
    try {
      const disconnected = await api("/vpn/disconnect", { method: "POST" });
      queryClient.setQueryData(["vpnStatus"], disconnected);
      await queryClient.invalidateQueries({ queryKey: ["vpnStatus"] });
      await queryClient.invalidateQueries({ queryKey: ["status"] });
    } catch (reason) {
      setError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={`vpn ${vpn?.connected ? "ok" : ""}`}>
      <span className="dot" />
      {vpn?.connected ? "tun0 연결됨" : "VPN 연결 안 됨"}
      <small>{vpn?.tun0 || "Tunnel 주소 없음"}</small>
      <div className="vpnActions">
        <label>
          {busy ? "처리 중…" : ".ovpn 선택"}
          <input
            type="file"
            accept=".ovpn"
            disabled={busy}
            onChange={(event) =>
              event.target.files?.[0] && prepare(event.target.files[0])
            }
          />
        </label>
        {vpn?.connected && (
          <button disabled={busy} onClick={disconnect}>
            연결 해제
          </button>
        )}
      </div>
      {error && <em>{error}</em>}
      {prepared && <div className="modal" role="dialog"
        aria-label="VPN 연결 승인">
        <div>
          <span>ROOT NETWORK OPERATION</span>
          <h2>VPN 연결 검토</h2>
          <p>파일명: <b>{prepared.file_name}</b></p>
          <p>SHA-256: <code>{prepared.sha256}</code></p>
          <p>프로필명: <b>{prepared.profile_name}</b></p>
          <p>실행 작업:</p>
          <ul>{prepared.actions.map((action: string) =>
            <li key={action}>{action}</li>)}</ul>
          <footer>
            <button disabled={busy}
              onClick={() => setPrepared(undefined)}>취소</button>
            <button className="danger" disabled={busy}
              onClick={connect}>확인 후 연결</button>
          </footer>
        </div>
      </div>}
    </div>
  );
}
