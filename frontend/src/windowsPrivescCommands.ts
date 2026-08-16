// Manual Windows privesc checklist -- same shape/spirit as
// linuxPrivescCommands.ts: copy-only reference, nothing runs on its own.
// WinPEAS (PrivescSessionPanel's/manual-shell 세션의 "WinPEAS 명령 셸에 입력"
// 버튼) already automates most of this in one pass; this exists for knowing
// WHERE to look by hand -- e.g. PowerShell history is the single most common
// "service account's password turns out to be the domain admin's too"
// discovery on Windows boxes (HTB Archetype 등), but until this file existed
// there was no way to send that lookup into an already-open evil-winrm/
// manual-shell session without leaving the graph for the SSH/wmiexec-only
// catalog runner in PostExploitationWorkspace.
export type PrivescCommand = { label: string; command: string; note?: string };
export type PrivescCategory = {
  id: string;
  title: string;
  description: string;
  commands: PrivescCommand[];
};

export const windowsPrivescCategories: PrivescCategory[] = [
  {
    id: "win-basic-info",
    title: "기본 정보 수집",
    description: "현재 권한, OS 버전, 로컬 사용자 목록부터 확인합니다 -- 이후 어떤 " +
      "익스플로잇이 말이 되는지가 여기서 갈립니다.",
    commands: [
      { label: "현재 사용자", command: "whoami" },
      { label: "현재 권한·그룹", command: "whoami /priv & whoami /groups",
        note: "SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege가 Enabled면 " +
          "PrintSpoofer/JuicyPotato류 토큰 악용으로 바로 SYSTEM 상승이 가능한 경우가 많습니다." },
      { label: "OS·패치 버전", command: "systeminfo",
        note: "출력이 너무 길면 systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" 로 좁히세요." },
      { label: "로컬 사용자 목록", command: "net user" },
      { label: "로컬 관리자 그룹", command: "net localgroup administrators" },
      { label: "네트워크 인터페이스", command: "ipconfig /all",
        note: "이 호스트를 통해 다른 내부 네트워크로 피벗할 수 있는지 확인." },
    ],
  },
  {
    id: "win-powershell-history",
    title: "PowerShell 히스토리·저장된 자격증명",
    description: "서비스 계정이 관리자 계정과 같은 비밀번호를 쓰거나, 예전에 입력한 명령에 " +
      "평문 비밀번호가 그대로 남아있는 경우가 흔합니다(HTB Archetype이 정확히 이 패턴).",
    commands: [
      { label: "PowerShell 명령 히스토리", command: "type (Get-PSReadlineOption).HistorySavePath",
        note: "cmd.exe가 아니라 PowerShell에서 실행해야 합니다. 기본 경로는 " +
          "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt." },
      { label: "저장된 자격증명(cmdkey)", command: "cmdkey /list",
        note: "목록만 보여주고 비밀번호 자체는 안 나오지만, 어떤 계정으로 runas /savecred가 " +
          "가능한지 알 수 있습니다." },
      { label: "무인 설치 응답 파일(Unattend.xml)", command: "dir /s /b C:\\Unattend.xml " +
        "C:\\Windows\\Panther\\Unattend.xml C:\\Windows\\Panther\\Unattend\\Unattend.xml " +
        "2>nul & type C:\\Windows\\Panther\\Unattend.xml 2>nul",
        note: "AD 이미지 배포 시 로컬 관리자 비밀번호가 Base64로 평문 저장되는 경우가 있습니다." },
      { label: "IIS web.config 연결 문자열", command: "findstr /si password " +
        "C:\\inetpub\\wwwroot\\web.config 2>nul",
        note: "DB 연결 문자열에 평문 비밀번호가 들어있는 경우가 흔합니다." },
      { label: "레지스트리 AutoLogon 비밀번호", command: "reg query " +
        "\"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\"",
        note: "DefaultPassword 값이 평문으로 남아있는 경우가 있습니다." },
    ],
  },
  {
    id: "win-services-tasks",
    title: "서비스 권한·예약 작업",
    description: "SYSTEM/관리자로 도는 서비스나 예약 작업의 실행 파일에 현재 사용자가 " +
      "쓰기 권한을 가진 경우, 그걸 통해 권한 상승을 얻을 수 있습니다.",
    commands: [
      { label: "서비스 목록", command: "wmic service get name,displayname,pathname,startmode" },
      { label: "따옴표 없는 서비스 경로 (Unquoted Service Path)",
        command: "wmic service get name,displayname,pathname,startmode | " +
          "findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\\\"\"",
        note: "경로에 공백이 있고 따옴표가 없으면, 경로 중간에 악성 실행 파일을 심어 " +
          "서비스 시작 시 대신 실행되게 만들 수 있습니다." },
      { label: "서비스 실행 파일 쓰기 권한 확인 (accesschk)",
        command: "accesschk.exe -uwcqv \"%username%\" *",
        note: "Sysinternals accesschk가 대상에 없으면 이 앱의 권한 상승 파일서버로 올려서 " +
          "쓰세요(WinPEAS 서버 시작과 같은 tun0 파일서버)." },
      { label: "예약 작업 목록", command: "schtasks /query /fo LIST /v" },
      { label: "AlwaysInstallElevated 레지스트리 확인",
        command: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer " +
          "/v AlwaysInstallElevated & reg query " +
          "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
        note: "두 키 모두 1이면 임의 .msi를 SYSTEM 권한으로 설치할 수 있습니다(msfvenom -f msi)." },
    ],
  },
];
