import {Button} from "./ui";
import OperatorContext from "./OperatorContext";
import {profileLabel, toolProfileGroups,
  type Profile} from "./scanCenterModel";

export default function ScanProfileComposer({tool, targetIp, targetError,
  onTargetIpChange, profiles, profileId,
  onSelectProfile, profile, ports, topPorts, onPortsChange, onTopPortsChange,
  onUpload, previewCommand, canReview, onReviewScan, vpnConnected, vpnAddress,
  scopeConfirmed, commandDraft = previewCommand || "", commandDirty = false,
  commandContextBound = true, commandEngineBound = true, onCommandChange = () => undefined,
  onRestoreCommand = () => undefined}: {
  tool: "nmap" | "masscan";
  targetIp: string; targetError: string;
  onTargetIpChange: (value: string) => void;
  profiles?: Profile[];
  profileId?: number;
  onSelectProfile: (id: number) => void;
  profile?: Profile;
  ports: string; topPorts: string;
  onPortsChange: (value: string) => void;
  onTopPortsChange: (value: string) => void;
  onUpload: (file: File) => void;
  previewCommand?: string;
  canReview: boolean;
  onReviewScan: () => void;
  vpnConnected?: boolean;
  vpnAddress?: string;
  scopeConfirmed?: boolean;
  commandDraft?: string;
  commandDirty?: boolean;
  commandContextBound?: boolean;
  commandEngineBound?: boolean;
  onCommandChange?: (value: string) => void;
  onRestoreCommand?: () => void;
}) {
  return <>
    <section className="scanSession" aria-label="스캔 명령 세션">
      <OperatorContext scope="target / scan"
        prompt={`[${targetIp.trim() || "no-target"}] scan $`}
        comment={profile ? profileLabel[profile.kind]?.description || profile.description : "대상과 명령 프로필을 선택하세요"}
        facts={[
          {label: "iface", value: vpnConnected ? vpnAddress || "tun0" : "offline", tone: vpnConnected ? "ready" : "warn"},
        ]}
        actions={<label className="importScan">IMPORT XML<input type="file" accept=".xml"
          aria-label="기존 Nmap XML 결과 가져오기"
          onChange={(e) => e.target.files?.[0] && onUpload(e.target.files[0])} /></label>} />

      <div className="scanSession__setup">
        <div className="targetSetup">
          <label className="fieldRow">
            <span>IP</span>
            <input aria-label="대상 IP" placeholder="10.10.10.10" value={targetIp}
              onChange={(e) => onTargetIpChange(e.target.value)} />
          </label>
          {targetError && <span className="fieldError">{targetError}</span>}
        </div>
        <div className="profilePicker">
          <label htmlFor="nmap-profile">COMMAND PROFILE</label>
          <select id="nmap-profile" value={profileId || ""}
            onChange={(e) => onSelectProfile(+e.target.value)}>
            {toolProfileGroups[tool].map((group) => (
              <optgroup key={group.label} label={group.label}>
                {group.kinds.flatMap((kind) => {
                  const item = profiles?.find((candidate) => candidate.kind === kind);
                  return item ? <option key={item.id} value={item.id}>
                    {profileLabel[item.kind]?.name || item.name}
                  </option> : [];
                })}
              </optgroup>
            ))}
          </select>
        </div>
      </div>

      <div className="scanCommandDeck">
        <div className="scanCommandDeck__label">
          <span>REPL / EDITABLE ARGV</span>
          <small>{commandDirty ? "operator modified" : commandDraft ? "ready" : canReview ? "ready to stage" : "waiting for context"}</small>
        </div>
        <label className="scanCommandDeck__prompt">
          <b>$</b>
          <textarea aria-label="스캔 명령" rows={2}
            spellCheck={false} value={commandDraft}
            placeholder={canReview ? "RUN을 눌러 Target과 명령을 준비하세요" : "IP와 프로필을 선택하세요"}
            onChange={(event) => onCommandChange(event.target.value)} />
        </label>
        {commandDirty && <div className="scanCommandDeck__provenance" aria-live="polite">
          <span className="is-modified">OPERATOR EDIT</span>
          {!commandContextBound && <span className="is-drift">TARGET CHANGED · EXECUTION LOCKED</span>}
          {!commandEngineBound && <span className="is-drift">ENGINE CHANGED · EXECUTION LOCKED</span>}
          {commandContextBound && commandEngineBound && !scopeConfirmed &&
            <span className="is-pending">SCOPE REVIEW REQUIRED</span>}
          <button type="button" onClick={onRestoreCommand}>RESTORE PROFILE</button>
        </div>}
        <div className="scanCommandDeck__controls">
          {profile?.arguments.includes("{top_ports}") && (
            <input aria-label="상위 포트 수" type="text" inputMode="numeric"
              pattern="[0-9]*" value={topPorts}
              onChange={(e) => onTopPortsChange(e.target.value.replace(/[^0-9]/g, ""))}
              placeholder="상위 포트 수 (1–65535)" />
          )}
          {profile?.arguments.includes("{ports}") && (
            <input aria-label="특정 포트" value={ports}
              onChange={(e) => onPortsChange(e.target.value)}
              placeholder="예: 22,80,443,8000-8100" />
          )}
          <Button variant="primary" disabled={!canReview || (!!commandDraft.trim() &&
            (!commandContextBound || !commandEngineBound))}
            onClick={onReviewScan}>
            RUN ↵
          </Button>
        </div>
      </div>
    </section>
  </>;
}
