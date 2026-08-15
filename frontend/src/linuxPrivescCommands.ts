// Manual Linux privesc checklist -- copy-only reference, same spirit as
// sqlPayloads.ts/lfiPayloads.ts: nothing here runs automatically or judges
// success, the operator reads each command, decides whether it applies, and
// either copies it or sends it into their own shell one at a time. LinPEAS
// (PrivescSessionPanel's existing "LinPEAS 명령 셸에 입력" button) already
// automates most of this in one pass; this list exists for the case that
// prompted it -- knowing WHERE to look (e.g. a service's config file lives
// in a different path depending on the distro's packaging) without needing
// to already remember the convention or wait on a full LinPEAS run.
export type PrivescCommand = { label: string; command: string; note?: string };
export type PrivescCategory = {
  id: string;
  title: string;
  description: string;
  commands: PrivescCommand[];
};

export const linuxPrivescCategories: PrivescCategory[] = [
  {
    id: "basic-info",
    title: "기본 정보 수집",
    description: "권한, 배포판, 커널 버전부터 확인합니다 -- 이후 모든 탐색 방향(어떤 익스플로잇이 " +
      "말이 되는지, 설정 파일이 어느 배포판 경로에 있을지)이 여기서 갈립니다.",
    commands: [
      { label: "현재 사용자·그룹", command: "id" },
      { label: "sudo 권한", command: "sudo -l",
        note: "리버스쉘 등 완전한 tty가 없는 셸에서는 비밀번호가 맞아도 " +
          "\"a terminal is required\"로 실패할 수 있습니다 -- SSH 등으로 " +
          "완전한 tty를 얻은 뒤 다시 시도하세요." },
      { label: "커널·아키텍처", command: "uname -a" },
      { label: "배포판 식별", command: "cat /etc/os-release 2>/dev/null || cat /etc/issue",
        note: "Debian/Ubuntu 계열인지 RHEL/CentOS 계열인지에 따라 아래 " +
          "서비스 설정 파일 경로가 달라집니다." },
      { label: "PATH·환경변수", command: "echo $PATH; env" },
    ],
  },
  {
    id: "suid-cap",
    title: "SUID / Capabilities",
    description: "루트 소유 SUID 바이너리나 파일 capability는 GTFOBins에서 바로 검색해볼 수 있는 " +
      "가장 흔한 권한 상승 경로입니다. find는 시스템 전체를 훑으므로 시간이 걸릴 수 있습니다.",
    commands: [
      { label: "SUID 바이너리 전체 검색", command: "find / -perm -4000 -type f 2>/dev/null" },
      { label: "SGID 바이너리 전체 검색", command: "find / -perm -2000 -type f 2>/dev/null" },
      { label: "파일 capability 검색", command: "getcap -r / 2>/dev/null",
        note: "SUID만 보면 놓치는 경로입니다 -- capability만으로도 " +
          "루트급 동작(예: cap_setuid)이 가능한 바이너리가 있을 수 있습니다." },
    ],
  },
  {
    id: "cron-services",
    title: "크론 / 서비스 설정 파일",
    description: "루트로 도는 예약 작업이나 서비스 설정에 현재 사용자가 쓰기 권한을 가진 경우, " +
      "그 파일을 통해 루트 권한으로 코드가 실행되게 만들 수 있습니다.",
    commands: [
      { label: "시스템 크론탭", command: "cat /etc/crontab 2>/dev/null" },
      { label: "크론 디렉터리", command: "ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null" },
      { label: "사용자 크론탭", command: "ls -la /var/spool/cron/crontabs/ 2>/dev/null" },
      { label: "루트로 도는 프로세스", command: "ps aux | grep '^root'" },
      { label: "쓰기 가능한 systemd 유닛", command: "find /etc/systemd/system /lib/systemd/system " +
        "-writable -type f 2>/dev/null" },
    ],
  },
  {
    id: "config-paths",
    title: "흔한 서비스 설정 파일 위치",
    description: "같은 서비스라도 배포판 패키징 관례에 따라 설정 파일 경로가 다릅니다 -- 현재 " +
      "디렉터리(예: DB data 디렉터리)에서 안 보인다고 설정이 없는 게 아니라, 다른 경로에 " +
      "분리돼 있을 뿐인 경우가 많습니다.",
    commands: [
      { label: "PostgreSQL 인증 설정 (Debian/Ubuntu)",
        command: "cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null",
        note: "데이터 디렉터리(/var/lib/postgresql/<버전>/main)와 설정 디렉터리가 " +
          "분리돼 있는 Debian/Ubuntu apt 패키징 관례입니다." },
      { label: "PostgreSQL 인증 설정 (RHEL/CentOS)",
        command: "cat /var/lib/pgsql/data/pg_hba.conf 2>/dev/null",
        note: "RHEL 계열은 데이터·설정이 같은 디렉터리에 있는 경우가 많습니다." },
      { label: "MySQL/MariaDB 설정", command: "cat /etc/mysql/my.cnf /etc/mysql/mariadb.conf.d/*.cnf " +
        "2>/dev/null" },
      { label: "Apache 설정 (Debian)", command: "cat /etc/apache2/apache2.conf 2>/dev/null" },
      { label: "Apache 설정 (RHEL, httpd)", command: "cat /etc/httpd/conf/httpd.conf 2>/dev/null" },
      { label: "SSH 서버 설정", command: "cat /etc/ssh/sshd_config 2>/dev/null" },
    ],
  },
  {
    id: "writable-shell",
    title: "쓰기 가능 파일 / 셸 안정화",
    description: "루트가 소유하지만 현재 사용자가 쓸 수 있는 파일을 찾거나, 비인터랙티브 리버스쉘을 " +
      "완전한 tty로 업그레이드합니다.",
    commands: [
      { label: "루트 소유·전체 쓰기 가능 파일", command: "find / -writable -user root -type f " +
        "2>/dev/null | grep -v -E '^/(proc|sys)'" },
      { label: "PATH 상 쓰기 가능한 디렉터리", command: "echo $PATH | tr ':' '\\n' | " +
        "xargs -I{} find {} -maxdepth 0 -writable 2>/dev/null" },
      { label: "tty 업그레이드 (python3)", command: "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
        note: "이어서 Ctrl+Z → stty raw -echo; fg → export TERM=xterm 순으로 실행하면 " +
          "sudo 비밀번호 프롬프트 등 완전한 tty가 필요한 명령도 정상 동작합니다." },
    ],
  },
];
