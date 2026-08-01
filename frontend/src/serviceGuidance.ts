export type ServiceGuidance = {
  title: string;
  command: string;
  steps: string[];
  accountCandidates: string[];
  verificationCommands?: string[];
};

const aliases: Record<string, "telnet" | "ftp" | "ssh" | "smb"> = {
  telnet: "telnet",
  ftp: "ftp",
  ssh: "ssh",
  smb: "smb",
  "microsoft-ds": "smb",
  "netbios-ssn": "smb",
};

export function getServiceGuidance(
  serviceName: string,
  host: string,
  port: number,
): ServiceGuidance | null {
  const service = aliases[serviceName.toLowerCase()];
  if (!service || !host || !port) return null;

  if (service === "telnet") {
    return {
      title: "Telnet 수동 접속",
      command: `telnet ${host} ${port}`,
      steps: [
        "연결 배너에서 제품과 버전 단서를 확인합니다.",
        "login: 프롬프트가 나타나면 사용자가 검토한 계정 하나를 직접 입력합니다.",
        "로그인에 성공하면 아래 읽기 전용 명령으로 설치된 Telnet 서버 패키지 버전을 확인합니다.",
        "응답과 식별 근거를 서비스 메모 또는 Evidence에 기록합니다.",
      ],
      accountCandidates: ["root", "admin", "user"],
      verificationCommands: [
        "/usr/sbin/in.telnetd --version 2>&1 || telnetd --version 2>&1",
        "dpkg-query -W 'telnetd*' 'inetutils-telnetd*' 2>/dev/null",
        "rpm -q telnet-server 2>/dev/null",
      ],
    };
  }
  if (service === "ftp") {
    return {
      title: "FTP 수동 접속",
      command: `ftp ${host} ${port}`,
      steps: [
        "서버 배너와 익명 접속 허용 여부를 확인합니다.",
        "Name 프롬프트에서 사용자가 검토한 계정 하나를 직접 입력합니다.",
        "접근 가능한 디렉터리와 읽기·쓰기 권한을 기록합니다.",
      ],
      accountCandidates: ["anonymous", "ftp", "admin"],
    };
  }
  if (service === "ssh") {
    return {
      title: "SSH 수동 접속",
      command: `ssh -p ${port} <account>@${host}`,
      steps: [
        "호스트 키와 서버 배너를 확인합니다.",
        "<account>를 사용자가 검토한 계정으로 바꾼 뒤 전체 명령을 확인합니다.",
        "인증 결과와 서버 식별 근거를 기록합니다.",
      ],
      accountCandidates: ["root", "admin", "user"],
    };
  }
  return {
    title: "SMB 수동 접속",
    command: `smbclient -L //${host} -p ${port} -U <account>`,
    steps: [
      "서버와 도메인 배너를 확인합니다.",
      "<account>를 사용자가 검토한 계정으로 바꾼 뒤 전체 명령을 확인합니다.",
      "열람 가능한 공유와 접근 결과를 기록합니다.",
    ],
    accountCandidates: ["guest", "administrator", "admin"],
  };
}
