import {profileLabel, privilegedKinds, toolProfileGroups,
  type Profile, type Target} from "./scanCenterModel";

export default function ScanProfileComposer({tool, targetIp, targetName, targetError,
  onTargetIpChange, onTargetNameChange, onCreateTarget, profiles, profileId,
  onSelectProfile, profile, target, ports, topPorts, onPortsChange, onTopPortsChange,
  onUpload, previewCommand, previewReady, onReviewScan}: {
  tool: "nmap" | "masscan";
  targetIp: string; targetName: string; targetError: string;
  onTargetIpChange: (value: string) => void;
  onTargetNameChange: (value: string) => void;
  onCreateTarget: () => void;
  profiles?: Profile[];
  profileId?: number;
  onSelectProfile: (id: number) => void;
  profile?: Profile;
  target?: Target;
  ports: string; topPorts: string;
  onPortsChange: (value: string) => void;
  onTopPortsChange: (value: string) => void;
  onUpload: (file: File) => void;
  previewCommand?: string;
  previewReady: boolean;
  onReviewScan: () => void;
}) {
  return <>
    <div className="targetSetup">
      <input
        aria-label="대상 IP"
        placeholder="대상 IP"
        value={targetIp}
        onChange={(e) => onTargetIpChange(e.target.value)}
      />
      <input
        aria-label="대상 이름"
        placeholder="대상 이름(선택)"
        value={targetName}
        onChange={(e) => onTargetNameChange(e.target.value)}
      />
      <button
        disabled={!targetIp.trim()}
        onClick={onCreateTarget}
      >
        대상 추가
      </button>
      {targetError && <span>{targetError}</span>}
    </div>
    <div className="profilePicker">
      <label htmlFor="nmap-profile">
        {tool === "masscan" ? "masscan 옵션" : "Nmap 옵션"}
      </label>
      <select
        id="nmap-profile"
        value={profileId || ""}
        onChange={(e) => onSelectProfile(+e.target.value)}
      >
        {toolProfileGroups[tool].map((group) => (
          <optgroup key={group.label} label={group.label}>
            {group.kinds.flatMap((kind) => {
              const item = profiles?.find(
                (candidate) => candidate.kind === kind,
              );
              return item ? (
                <option key={item.id} value={item.id}>
                  {profileLabel[item.kind]?.name || item.name}
                </option>
              ) : [];
            })}
          </optgroup>
        ))}
      </select>
      {profile && (
        <div>
          <b>{profileLabel[profile.kind]?.name || profile.name}</b>
          <small>
            {profileLabel[profile.kind]?.description ||
              profile.description}
          </small>
          <code>
            {`${privilegedKinds.has(profile.kind) ? "sudo " : ""}${
              profile.engine || "nmap"
            } ${profile.arguments
              .replace("{ports}", ports)
              .replace("{top_ports}", topPorts)} ${target?.ip || "<IP>"}`}
          </code>
        </div>
      )}
    </div>
    <div className="scanHero">
      <label className="importScan">
        기존 Nmap XML 결과 가져오기
        <input
          type="file"
          accept=".xml"
          onChange={(e) =>
            e.target.files?.[0] && onUpload(e.target.files[0])
          }
        />
      </label>
    </div>
    <div className="scanComposer">
      {profile?.arguments.includes("{top_ports}") && (
        <input
          aria-label="상위 포트 수"
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          value={topPorts}
          onChange={(e) =>
            onTopPortsChange(e.target.value.replace(/[^0-9]/g, ""))
          }
          placeholder="상위 포트 수 (1–65535)"
        />
      )}
      {profile?.arguments.includes("{ports}") && (
        <input
          aria-label="특정 포트"
          value={ports}
          onChange={(e) => onPortsChange(e.target.value)}
          placeholder="예: 22,80,443,8000-8100"
        />
      )}
      <code>
        {previewCommand || "대상과 프로필을 선택하세요"}
      </code>
      <button
        disabled={!previewReady}
        onClick={onReviewScan}
      >
        새 {profile?.engine === "masscan" ? "masscan" : "Nmap"} 스캔 검토
      </button>
    </div>
  </>;
}
