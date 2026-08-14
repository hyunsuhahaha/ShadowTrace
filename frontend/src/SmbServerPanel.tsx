// impacket-smbserver, opened as an in-page floating PTY (same
// autoFloat mechanism as Responder) so it keeps running while the tester
// triggers a forced-auth coercion (UNC-path LFI, PetitPotam, a malicious
// .library-ms, etc.) from another tab or workspace. Two uses for the same
// listener: an unauthenticated share alone is enough to capture a
// NetNTLMv2 hash when the target connects to it, and if the target can
// read files over that same share (e.g. a PHP LFI that accepts a UNC
// path), a webshell dropped into the share can be included directly --
// no hash-cracking step needed at all.
export default function SmbServerPanel({ targetId, onStartListener }: {
  targetId?: number;
  onStartListener: () => void;
}) {
  return (
    <section className="netexecCredCheck" aria-labelledby="smbserver-heading">
      <header>
        <h2 id="smbserver-heading">SMB 공유 서버 (impacket-smbserver)</h2>
      </header>
      <p className="netexecEvidenceMsg">
        인증 없이 접속 가능한 SMB 공유를 엽니다. 강제 인증 유도와 함께 쓰면 NetNTLMv2 해시가
        터미널에 그대로 뜨고, 대상이 UNC 경로로 파일을 읽어올 수 있으면 이 공유에 올려둔
        webshell을 직접 포함시켜 해시를 꺾지 않고도 RCE로 이어갈 수 있습니다. 공유 폴더는
        프로젝트의 targets/{"{host}"}/outputs/smb-share 아래이며, 여기 파일을 올려두고 쓰세요.
      </p>
      <button disabled={!targetId} onClick={onStartListener} style={{
        border: "1px solid #4c755f", borderRadius: 4, padding: "8px 12px",
        background: "#b8dec7", color: "#102019", fontSize: 10, fontWeight: 750,
      }}>
        SMB 공유 서버 시작
      </button>
    </section>
  );
}
