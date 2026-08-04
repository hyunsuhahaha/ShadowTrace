// Copy-only reference: every DB engine uses different syntax for the same
// basic "what's in here" steps once you have a working login. Nothing here
// runs automatically — same rationale as sqlPayloads.ts.
export type DbCommand = { label: string; command: string; note?: string };
export type DbExplorationGuide = { title: string; commands: DbCommand[] };

const guides: Record<string, DbExplorationGuide> = {
  mysql: {
    title: "MySQL 탐색 명령",
    commands: [
      { label: "데이터베이스 목록", command: "SHOW DATABASES;" },
      { label: "데이터베이스 선택", command: "USE <db>;" },
      { label: "테이블 목록", command: "SHOW TABLES;" },
      { label: "테이블 구조", command: "DESCRIBE <table>;" },
      { label: "전체 데이터 조회", command: "SELECT * FROM <table>;" },
      { label: "현재 사용자·권한", command: "SELECT CURRENT_USER(); SHOW GRANTS;" },
      { label: "버전 확인", command: "SELECT VERSION();" },
      { label: "파일 읽기", command: "SELECT LOAD_FILE('/etc/passwd');",
        note: "FILE 권한과 secure_file_priv 설정이 필요합니다." },
    ],
  },
  "ms-sql-s": {
    title: "MS SQL 탐색 명령",
    commands: [
      { label: "데이터베이스 목록", command: "SELECT name FROM sys.databases;" },
      { label: "데이터베이스 선택", command: "USE <db>;" },
      { label: "테이블 목록", command: "SELECT table_name FROM information_schema.tables;" },
      { label: "전체 데이터 조회", command: "SELECT * FROM <table>;" },
      { label: "현재 사용자·권한", command: "SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER('sysadmin');" },
      { label: "버전 확인", command: "SELECT @@VERSION;" },
      { label: "명령 실행 (xp_cmdshell)", command: "EXEC xp_cmdshell 'whoami';",
        note: "sysadmin 권한 필요, 먼저 활성화해야 할 수 있습니다(SQLi 참고 탭 참조)." },
    ],
  },
  postgresql: {
    title: "PostgreSQL 탐색 명령",
    commands: [
      { label: "데이터베이스 목록 (psql)", command: "\\l" },
      { label: "데이터베이스 목록 (SQL)", command: "SELECT datname FROM pg_database;" },
      { label: "데이터베이스 전환 (psql)", command: "\\c <db>" },
      { label: "테이블 목록 (psql)", command: "\\dt" },
      { label: "테이블 목록 (SQL)", command: "SELECT table_name FROM information_schema.tables;" },
      { label: "전체 데이터 조회", command: "SELECT * FROM <table>;" },
      { label: "현재 사용자·권한", command: "SELECT current_user; \\du" },
      { label: "버전 확인", command: "SELECT version();" },
      { label: "파일 읽기 (COPY)", command: "CREATE TEMP TABLE t(l text); COPY t FROM '/etc/passwd'; SELECT * FROM t;",
        note: "superuser 권한이 필요합니다." },
    ],
  },
  redis: {
    title: "Redis 탐색 명령",
    commands: [
      { label: "서버 정보", command: "INFO" },
      { label: "DB 개수 확인 후 전환", command: "SELECT <index>",
        note: "관계형 DB가 아니라 0부터 시작하는 숫자 인덱스로 구분됩니다." },
      { label: "키 목록", command: "KEYS *" },
      { label: "키 타입 확인", command: "TYPE <key>" },
      { label: "문자열 값 조회", command: "GET <key>" },
      { label: "해시/리스트/셋 조회", command: "HGETALL <key> / LRANGE <key> 0 -1 / SMEMBERS <key>" },
      { label: "설정 파일 경로 확인", command: "CONFIG GET dir" },
    ],
  },
  mongodb: {
    title: "MongoDB 탐색 명령",
    commands: [
      { label: "데이터베이스 목록", command: "show dbs" },
      { label: "데이터베이스 선택", command: "use <db>" },
      { label: "컬렉션 목록", command: "show collections" },
      { label: "전체 문서 조회", command: "db.<collection>.find().pretty()" },
      { label: "현재 사용자·권한", command: "db.runCommand({connectionStatus: 1})" },
      { label: "버전 확인", command: "db.version()" },
    ],
  },
};

export const getDbExplorationGuide = (serviceName = ""): DbExplorationGuide | undefined =>
  guides[serviceName.toLowerCase()];
