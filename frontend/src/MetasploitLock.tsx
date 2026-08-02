// OSCP exam rules allow Metasploit/Meterpreter against only one target for
// the whole exam, with no pivoting. This widget tracks which target (if
// any) a project has already committed to and warns before a second one
// gets used — it's a reminder surface, not an execution gate, since this
// app never runs Metasploit itself (see product_policy.py).
type Target = { id: number; name: string; ip: string };
export type ProjectWithLock = {
  id: number;
  metasploit_target_id?: number | null;
};

export default function MetasploitLock({
  project, targets, targetId, onSetLock,
}: {
  project?: ProjectWithLock;
  targets?: Target[];
  targetId?: number;
  onSetLock: (targetId: number | null) => void;
}) {
  if (!project || !targetId) return null;
  const lockedId = project.metasploit_target_id ?? null;
  const lockedTarget = targets?.find((item) => item.id === lockedId);

  if (lockedId === null) {
    return (
      <div className="msfLock msfLock--unset" title="OSCP 시험 규정: Metasploit·Meterpreter는 전체 시험에서 대상 1개에만 허용됩니다.">
        <span>Metasploit 미사용</span>
        <button onClick={() => onSetLock(targetId)}>이 대상에 사용 등록</button>
      </div>
    );
  }
  if (lockedId === targetId) {
    return (
      <div className="msfLock msfLock--current">
        <span>✓ 이 대상에서 Metasploit 사용 중</span>
        <button onClick={() => onSetLock(null)}>등록 해제</button>
      </div>
    );
  }
  return (
    <div className="msfLock msfLock--blocked" role="alert">
      <span>
        ⚠ {lockedTarget ? `${lockedTarget.name} (${lockedTarget.ip})` : "다른 대상"}에서
        이미 사용함 · 시험 규정상 대상 1개 제한
      </span>
      <button onClick={() => {
        if (window.confirm(
          `${lockedTarget?.ip || "이전 대상"}에서 이 대상으로 Metasploit 사용 등록을 ` +
          "변경할까요? 실제 시험에서는 대상 1개에만 Metasploit/Meterpreter를 쓸 수 있으므로, " +
          "연습이 아니라면 변경하지 마세요.",
        )) onSetLock(targetId);
      }}>변경(주의)</button>
    </div>
  );
}
