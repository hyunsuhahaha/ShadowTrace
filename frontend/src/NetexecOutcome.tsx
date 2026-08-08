import type {RunState, Service, Target} from "./enumerationModel";
import {buildFileTree, FileTreeView, parseTaggedTreeLines} from "./fileTree";

export type NetexecProtocol = "smb" | "ssh" | "winrm" | "rdp" | "mssql" | "ldap";
type ExecutionEvidence = {id: number; stdout?: string; stderr?: string};
export type AutoFileTreeState = {status: string; output: string};
type Actions = {
  openPsexec: () => void;
  openLateral: (kind: "wmiexec" | "smbexec" | "atexec") => void;
  openSsh: () => void; openWinrm: () => void; copyRdp: () => void;
  openMssql: () => void; openHashcat: () => void; openLookupsid: () => void;
  openMssqlRidBrute: () => void;
  captureEvidence: (execution: ExecutionEvidence, title: string) => void;
  promoteFinding: (execution: ExecutionEvidence, title: string, description: string) => void;
};

export default function NetexecOutcome({protocol, result, username, domain, target,
  service, evidenceMsg, actions, fileTree}: {
  protocol: NetexecProtocol; result?: RunState; username: string; domain: string;
  target?: Target; service?: Service; evidenceMsg: string; actions: Actions;
  fileTree?: AutoFileTreeState;
}) {
  const success = result?.status === "completed"
    && /^\[\+\]|pwn3d/im.test(result.stdout || "");
  if (!success && protocol !== "ldap") return null;
  const evidence = result?.id
    ? {id: result.id, stdout: result.stdout, stderr: result.stderr} : undefined;
  return <>
    {protocol === "smb" && /pwn3d/i.test(result?.stdout || "") &&
      <div className="netexecPwned"><b>로컬 관리자 권한 확인됨 (Pwn3d!)</b>
        <span>원문 출력은 실행 이력에서 확인하세요. 아래 버튼들은 같은 계정으로
          impacket 명령을 데스크톱 셸에 입력만 해둡니다 — 대상과 명령을 다시
          확인한 뒤 직접 Enter를 눌러야 실행됩니다. 하나가 막히면 다른 걸 시도하세요.</span>
        <div className="netexecPwnedActions">
          <button onClick={actions.openPsexec}>psexec</button>
          {(["wmiexec", "smbexec", "atexec"] as const).map((kind) =>
            <button key={kind} onClick={() => actions.openLateral(kind)}>{kind}</button>)}
        </div>
      </div>}
    {protocol === "smb" && success && <div className="netexecPwnedActions" style={{marginTop: "12px"}}>
      <button onClick={actions.openLookupsid}>SID 순환으로 사용자 열거 (lookupsid)</button>
    </div>}
    {protocol === "ssh" && success && <div className="netexecPwned">
      <b>SSH 인증 성공</b><span>원문 출력은 실행 이력에서 확인하세요. 아래 버튼은
        ssh 명령을 입력만 해둡니다. 대상을 확인한 뒤 직접 Enter를 누르세요.</span>
      <button onClick={actions.openSsh}>SSH 명령 준비하기</button>
    </div>}
    {protocol === "winrm" && success && <div className="netexecPwned">
      <b>WinRM 인증 성공</b><span>evil-winrm 명령을 입력만 해둡니다. 대상과 계정을
        확인한 뒤 직접 Enter를 눌러야 실행됩니다.</span>
      <button onClick={actions.openWinrm}>evil-winrm 명령 준비하기</button>
    </div>}
    {(protocol === "ssh" || protocol === "winrm") && success && fileTree && (
      <div className="netexecFileTree">
        <b>폴더·파일 트리 {fileTree.status === "running" ? "(자동 조회 중…)" : ""}</b>
        <FileTreeView node={buildFileTree(
          parseTaggedTreeLines(fileTree.output), protocol === "winrm" ? "\\" : "/")} />
      </div>
    )}
    {protocol === "rdp" && success && <div className="netexecPwned">
      <b>RDP 인증 성공</b><span>xfreerdp 명령을 클립보드에 복사합니다. 직접 터미널에서
        확인 후 붙여넣어 실행해야 합니다.</span>
      <button onClick={actions.copyRdp}>xfreerdp 명령 복사</button>
    </div>}
    {protocol === "mssql" && success && <div className="netexecPwned">
      <b>MS SQL 인증 성공</b><span>impacket-mssqlclient 명령을 입력만 해둡니다.
        대상과 계정을 확인한 뒤 직접 Enter를 눌러야 실행됩니다.</span>
      <button onClick={actions.openMssql}>impacket-mssqlclient 명령 준비하기</button>
    </div>}
    {protocol === "mssql" && success && <div className="netexecPwnedActions" style={{marginTop: "12px"}}>
      <button onClick={actions.openMssqlRidBrute}>RID 순환으로 사용자 열거 (--rid-brute)</button>
    </div>}
    {protocol === "ldap" && <div className="netexecPwnedActions" style={{marginTop: "12px"}}>
      <button onClick={actions.openHashcat}>Kerberoast 해시 → hashcat 명령 준비</button>
    </div>}
    {success && evidence && <div className="netexecEvidence">
      <button onClick={() => actions.captureEvidence(evidence,
        `${protocol.toUpperCase()} 자격증명 검증 · ${username}`)}>Evidence로 저장</button>
      <button onClick={() => actions.promoteFinding(evidence,
        `${protocol.toUpperCase()} 유효 자격증명 · ${username}`,
        `${target?.ip} ${service?.port}/${service?.name}에 대해 `
          + `${domain ? domain + "\\" : ""}${username} 계정으로 NetExec ${protocol} 인증에 성공함.`
      )}>Finding(Draft)으로 승격</button>
      {evidenceMsg && <span>{evidenceMsg}</span>}
    </div>}
  </>;
}
