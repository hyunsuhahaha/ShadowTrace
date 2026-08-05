import {elapsed, type Automation, type Profile, type Scan} from "./scanCenterModel";
import {statusCopy as statusLabel} from "./ui";

export default function ScanJobStatus({selected, clock, streamState, lastEventAt,
  processAlive, selectedProfile, automation, chainedScan, openTcpPorts,
  onOpenChainedScan, onUseDiscoveredPorts}: {
  selected?: Scan; clock: number;
  streamState: "idle" | "connecting" | "connected" | "disconnected";
  lastEventAt?: number; processAlive?: boolean; selectedProfile?: Profile;
  automation?: Automation; chainedScan?: Scan; openTcpPorts: number[];
  onOpenChainedScan: (id: number) => void; onUseDiscoveredPorts: () => void;
}) {
  return <>
    {selected && (
      <section
        className={`jobStatus jobStatus--${selected.status}`}
        aria-live="polite"
        aria-label="현재 스캔 상태"
      >
        <span className="jobStatus__dot" aria-hidden="true" />
        <div>
          <b>
            스캔 #{selected.id} · {statusLabel[selected.status] || selected.status}
          </b>
          <small>
            {selected.status === "queued" && "실행 순서를 기다리고 있습니다."}
            {["running", "processing"].includes(selected.status) &&
              (() => {
                const engineName =
                  (selectedProfile?.engine === "masscan" ? "masscan" : "Nmap");
                return processAlive
                  ? `백엔드가 ${engineName} 프로세스 실행을 확인했습니다. 전체 포트 탐색은 출력 없이 오래 걸릴 수 있습니다.`
                  : `${engineName}이(가) 실행 중입니다. 다음 상태 신호를 기다리고 있습니다.`;
              })()}
            {selected.status === "completed" && "스캔과 결과 처리가 완료되었습니다."}
            {selected.status === "failed" &&
              `스캔에 실패했습니다.${selected.error ? ` ${selected.error}` : ""}`}
            {selected.status === "stopped" && "사용자가 스캔을 중단했습니다."}
            {selected.status === "interrupted" && "서버 중단으로 스캔이 종료되었습니다."}
          </small>
        </div>
        <dl>
          <div>
            <dt>경과 시간</dt>
            <dd>{elapsed(selected, clock)}</dd>
          </div>
          <div>
            <dt>실시간 연결</dt>
            <dd>
              {streamState === "connected"
                ? "연결됨"
                : streamState === "connecting"
                  ? "연결 중"
                  : streamState === "disconnected"
                    ? "끊김 · 상태 자동 확인 중"
                    : ["completed", "failed", "stopped", "interrupted"].includes(selected.status)
                      ? "완료" : "대기"}
            </dd>
          </div>
          <div>
            <dt>마지막 상태 신호</dt>
            <dd>
              {lastEventAt
                ? `${Math.max(0, Math.floor((clock - lastEventAt) / 1000))}초 전`
                : "대기 중"}
            </dd>
          </div>
        </dl>
        {["running", "processing"].includes(selected.status) &&
          lastEventAt && clock - lastEventAt > 30000 && (
            <p className="jobStatus__warning" role="alert">
              30초 이상 상태 신호가 없습니다. 백엔드 연결을 확인하거나 스캔을 취소하세요.
            </p>
          )}
      </section>
    )}
    {selected?.status === "completed" && automation && (
      <section className="scanAutomation" aria-label="자동 증적 처리 결과">
        <div>
          <b>자동 증적 처리 완료</b>
          <span>
            Evidence {automation.evidence_count}개 저장 · 검토할 Finding 후보{" "}
            {automation.finding_count}개
          </span>
        </div>
        <a href="#reports">
          {automation.review_required
            ? "Reports에서 후보 검토"
            : "Reports 열기"}
        </a>
        <small>
          후보는 오탐 검토 전까지 Internal · Needs Review 상태이며 Client 보고서에 포함되지 않습니다.
        </small>
      </section>
    )}
    {selected?.status === "completed" && chainedScan && (
      <section className="scanAutomation" aria-label="자동 생성된 상세 스캔">
        <div>
          <b>자동 상세 스캔 대기열에 추가됨</b>
          <span>
            발견된 포트로 Nmap 상세 스캔 #{chainedScan.id} ·{" "}
            {statusLabel[chainedScan.status] || chainedScan.status}
          </span>
        </div>
        <button type="button" onClick={() => onOpenChainedScan(chainedScan.id)}>
          상세 스캔 열기
        </button>
      </section>
    )}
    {selected?.status === "completed" &&
      !chainedScan &&
      openTcpPorts.length > 0 && (
        <section className="scanAutomation" aria-label="발견된 포트로 상세 스캔 준비">
          <div>
            <b>열린 포트 {openTcpPorts.length}개 발견</b>
            <span>{openTcpPorts.join(", ")}</span>
          </div>
          <button type="button" onClick={onUseDiscoveredPorts}>
            발견된 포트로 상세 스캔 준비
          </button>
          <small>
            포트 필드와 프로필이 채워집니다. 검토 후 직접 스캔을 실행하세요.
          </small>
        </section>
      )}
  </>;
}
