# ShadowTrace

*Passive pentest activity recorder.*

Kali Linux에서 승인된 단일 대상 침투 테스트의 활동, 발견, 수동 열거,
증적과 보고서를 한곳에 기록하는 로컬 전용 워크스페이스입니다.

React UI, FastAPI API, SQLite 저장소로 구성되며 모든 명령은 사용자가 대상과 최종
명령을 검토하고 명시적으로 승인한 뒤 실행됩니다. 자동 취약점 판정이나 자율 공격
체인은 제공하지 않습니다.

> 본인이 소유하거나 명시적으로 허가받은 시스템에서만 사용하세요. OSCP 시험에서는
> 당시 적용되는 공식 시험 규정을 우선 확인해야 합니다. 저장소의
> [정책 메모](docs/OSCP_POLICY.md)는 참고 자료이며 최신 규정을 대신하지 않습니다.

## Passive capture MVP

ShadowTrace를 실행한 동안 기존 Kali terminal에서 평소처럼 작업하면 eBPF observer가
사용자 process 계보, fd 0/1/2 I/O, socket lifecycle 일부와 변경형 filesystem syscall을
원시 이벤트로 기록합니다. 이벤트에는 PID/TTY/cwd/namespace context, sequence, loss,
capture state와 confidence가 붙습니다. PTY 입력은 userspace 처리 시점에 terminal ECHO가
켜졌다고 확인된 경우만 저장하며, 나머지는 byte count만 남깁니다. syscall과 확인 사이
상태 변경 race가 있으므로 비밀값 비수집을 절대 보장하는 보안 경계로 보지는 않습니다.

현재 의미 해석과 Graph 자동 반영은 여전히 `nmap` MVP만 지원합니다. 단일 literal IP의
표준 port table을 원본 출력과 SHA-256 Evidence로 보존하고 Target/Service에 반영하며,
다른 원시 이벤트를 곧바로 Observation이나 Finding으로 승격하지 않습니다. 모든 Kali
활동 또는 행동별 Graph node를 보장하지 않습니다.

Raw event ingest 뒤에는 다음 best-effort reconstruction이 실행됩니다.

```text
RawActivityEvent → ProcessInstance → TerminalSession → CommandActivity
                                      └→ RemoteSessionCandidate
```

PGID, SID, controlling TTY, stdio FD target과 시간 근접성으로 pipeline, redirect,
background job과 PTY input을 묶습니다. shell builtin 및 SSH 내부 입력은 실행이 확인된
명령이 아니라 confidence가 낮은 candidate입니다. 이 계층은 Graph를 변경하지 않습니다.

커널 준비 상태와 live smoke는 다음처럼 확인합니다.

```bash
./scripts/passive-preflight.sh
./scripts/start.sh
./scripts/passive-live-smoke.py
```

두 번째 명령은 sudo가 필요합니다. preflight가 새 kernel image 설치를 안내한 경우에는
설치 후 재부팅하고 `uname -r`과 matching headers를 다시 확인해야 합니다.

```bash
sudo apt install python3-bpfcc
./scripts/start.sh
```

서버 실행 진입점은 `scripts/start.sh` 하나이며 migration, sudo 전환,
passive observer와 FastAPI lifecycle을 함께 관리합니다.

여러 Project가 같은 IP를 갖거나 새 Target을 어느 Project에 넣을지 모호하면
activity를 `unresolved`로 보존하고 도메인과 Graph는 변경하지 않습니다.

## 현재 구현된 기능

### Scan Center

- 프로젝트 및 Target 등록
- 빠른 스캔, 전체 TCP, 선택 포트 상세 등 Nmap 프로필
- 실행 전 명령 미리보기와 범위 확인
- 스캔 대기열, 동시 실행 제한, SSE 실시간 출력, 중단 및 재실행
- Nmap XML 가져오기와 `-oA` 산출물 보존
- 호스트, 포트, 서비스 및 NSE 관찰값 파싱
- 스캔 간 변화 비교와 JSON, CSV 내보내기
- 원본 파일 다운로드와 SHA-256 기록

### Service Enumeration

- 발견된 서비스별 조사 대시보드
- Hostname, 운영체제, 제품 및 버전 확인 상태
- YAML 기반 서비스별 정적 명령 카탈로그
- 명령 미리보기, 위험도 표시, 승인 후 실행
- 실행 상태, 출력, 이력, 중단 및 결과 저장
- 완료된 확인 명령을 하단 후보 목록에서 자동 제외
- 서비스 제품, 버전, 메모와 태그 수동 보정
- SSH, FTP, Telnet, smbclient 등 대화형 데스크톱 터미널
- FTP anonymous 인증 확인 후 로그인된 FTP 터미널 자동 실행
- 프로토콜별 제한된 자격증명 점검과 원본 결과 표시
- SMB 공유 재귀 파일 목록: 선택한 공유는 smbclient, 대상 전체 공유는 NetExec
  spider_plus로 조회 (다운로드 없이 목록만 수집)
- 사용자가 입력한 단일 계정을 SMB·SSH·WinRM·RDP·MS SQL·LDAP에 NetExec으로 검증
  (대입 공격이 아님). 성공 시 psexec·evil-winrm·mssqlclient 등 후속 명령을 셸에
  입력만 해두고 실행은 사용자가 직접 확인 후 진행
- Credential Store: 획득한 계정과 출처를 기록해 워크스페이스 전체에서 재사용.
  실제 비밀번호 저장은 명시적 opt-in이며 기본값은 힌트만 기록. 저장된 비밀번호는
  로컬 SQLite에만 있고 명령 자동채움에만 사용되며 검색·보고서에는 노출되지 않음

자격증명 점검의 상세 범위와 잠금 위험은
[프로토콜 인증 점검 문서](docs/OSCP_PROTOCOL_AUTH_AUDIT.md)에 정리되어 있습니다.

### Web Testing

- 메서드, URL, 헤더, 쿠키, 본문을 포함한 HTTP 요청 편집
- 폴더, 태그 및 사용자 변수
- 사용자가 작성한 요청의 단일 또는 명시적 반복 전송
- 프록시, TLS 검증 및 타임아웃 설정
- 응답 상태, 헤더, 본문, 크기와 소요 시간 기록
- 두 응답 비교와 원본 본문 다운로드

자동 페이로드 생성, 공격형 퍼징 및 취약점 판정은 포함하지 않습니다.

### Exploit Research

- 선택한 서비스의 제품과 버전을 기반으로 SearchSploit 후보 검색
- 사용자가 선택한 후보만 Research 항목으로 저장
- 로컬 Exploit-DB 원본 PoC 가져오기
- 읽기 전용 원본과 편집 가능한 working copy 분리
- SHA-256, 수정 사유, 민감 값과 unified diff 기록
- Python, Ruby, Perl, PHP, Node 또는 실행 파일의 일회성 로컬 실행
- 실행 전 argv, 파일 해시와 일회용 승인 토큰 재확인
- 타임아웃, 취소, stdout/stderr, 사용자 판정 및 Evidence 연결

외부 URL은 메모로만 저장하며 애플리케이션이 임의로 다운로드하지 않습니다.
SearchSploit 결과도 자동 취약점 판정이나 자동 익스플로잇 선택으로 사용하지 않습니다.

### Runbooks

- Target 및 Service에 적용하는 버전 고정형 체크리스트
- Target, FTP, SSH, HTTP, SMB, Database 등 18개 기본 Runbook 자동 설치
- 서비스명과 포트에 따른 설명 가능한 추천 및 추천 숨기기
- 기본 Runbook 복제, 사용자 Template 작성·발행·보관, JSON 가져오기·내보내기
- 단계별 수동 상태, 결과, 메모, 사유, 타이머와 Target 진행률
- Step과 기존 Command, Execution, Evidence 및 Credential 연결
- 조건부 Step, Observation 기록과 Finding 승격
- 활동 이력, blocked·suspicious·장기 미활동 요약, Finding Markdown 내보내기

기본 Runbook은 읽기 전용입니다. 변경이 필요하면 복제하여 사용자 Template로 관리합니다.
Runbook 적용은 체크리스트 snapshot만 만들며 명령을 실행하거나 결과를 판정하지 않습니다.

### Evidence

- 파일, 스크린샷, 명령 출력 및 Markdown 메모 저장
- 프로젝트, Target, Service, Scan, Execution 및 Research 연결
- 출처, 취득 시각, 민감도와 SHA-256 기록
- 중복 표시, 파일 미리보기 및 메타데이터 수정
- 선택한 증적과 manifest를 ZIP으로 내보내기

### AD Information

- 사용자, 그룹, 컴퓨터, 도메인 등 관찰 객체 기록
- 객체 간 관계 기록
- 검색과 종류 필터
- CSV 또는 JSON 가져오기

공격 경로나 권한 상승 경로를 자동 계산하지 않습니다.

### Sessions

- 사용자가 승인한 SSH 로컬, 원격 및 동적 포워딩
- 터널 PID, 상태, 로그와 종료 관리
- 웹 PTY 및 Kali 데스크톱 터미널 세션
- 세션 로그와 수명주기 기록

자동 피벗이나 자동 셸 획득은 수행하지 않습니다.

### Reports

- 사용자가 작성한 Markdown 기반 보고서
- 선택한 Evidence와 Exploit Research 결과 연결
- 누락 항목과 민감정보 검토
- Markdown, HTML 및 PDF 내보내기

### Operations 및 VPN

- 프로젝트 데이터 전체 검색
- 변경 작업 감사 이력
- SQLite와 산출물을 포함한 ZIP 백업
- `.ovpn` 파일 검증 및 NetworkManager 기반 연결과 해제
- `tun0` 주소, 라우팅 및 설치 도구 상태 표시

## 빠른 시작

### 요구 사항

- Kali Linux, Debian 또는 Ubuntu
- Python 3.11 이상
- Node.js와 npm
- `sudo`
- 기본 스캔용 `nmap`

선택 기능에 따라 Kali 도구가 추가로 필요합니다. 예:

```bash
sudo apt install nmap gobuster feroxbuster enum4linux-ng \
  smbclient openssh-client ftp exploitdb netexec
```

애플리케이션 의존성을 설치합니다.

```bash
./scripts/install.sh
```

개발 서버를 시작합니다.

```bash
./scripts/dev.sh
```

- UI: `http://127.0.0.1:5173`
- API 및 OpenAPI: `http://127.0.0.1:8000`, `http://127.0.0.1:8000/docs`

`dev.sh`는 일반 데스크톱 사용자로 실행해야 합니다. Vite는 현재 사용자로 실행되고,
네트워크 작업이 필요한 FastAPI 백엔드만 `sudo`를 통해 시작됩니다. 백엔드는
`127.0.0.1`에만 바인딩되며 시작할 때 sudo 인증을 한 번 요청할 수 있습니다.

### 프로덕션 빌드

```bash
./scripts/build.sh
./scripts/start.sh
```

`start.sh`는 빌드된 프론트엔드를 FastAPI에서 함께 제공합니다.

### 테스트

전체 백엔드 테스트와 프론트엔드 프로덕션 빌드:

```bash
./scripts/test.sh
```

개별 테스트:

```bash
.venv/bin/pytest backend/tests
cd frontend && npm test
```

## 기본 작업 흐름

1. Scan Center에서 프로젝트와 Target을 등록합니다.
2. 스캔 프로필과 최종 Nmap 명령을 검토한 뒤 실행하거나 기존 XML을 가져옵니다.
3. Runbooks에서 Target 또는 Service에 추천된 기본 절차를 적용합니다.
4. Service Enumeration에서 각 Step의 권장 명령을 검토하고 승인한 뒤 실행합니다.
5. 웹 서비스는 Web Testing에서 직접 작성한 HTTP 요청으로 검증합니다.
6. 필요한 경우 Exploit Research에서 후보와 PoC를 사용자가 직접 검토합니다.
7. Observation, Execution과 중요한 파일을 Evidence 및 Finding에 연결합니다.
8. Reports에서 확인한 사실과 증적으로 보고서를 작성합니다.
9. Operations에서 누락을 확인하고 백업을 생성합니다.

## 데이터 위치

기본값은 XDG 디렉터리 규칙을 따릅니다.

| 데이터 | 기본 경로 | 환경 변수 |
|---|---|---|
| 설정 및 VPN 파일 | `~/.config/oscp-workspace` | `OSCP_WORKSPACE_CONFIG` |
| SQLite DB | `~/.local/share/oscp-workspace/workspace.db` | `OSCP_WORKSPACE_DB` |
| 상태 및 PID | `~/.local/state/oscp-workspace` | `OSCP_WORKSPACE_STATE` |
| 프로젝트 산출물 | `~/OSCP-Workspace` | `OSCP_WORKSPACE_ROOT` |

대표적인 프로젝트 파일 구조:

```text
~/OSCP-Workspace/projects/<project>/targets/<target>/
├── outputs/
├── scans/
├── evidence/
└── exploit-research/<research-id>/
    ├── poc/<source-id>/original-*
    ├── poc/<source-id>/working-*
    └── executions/
```

설치, 개발 및 시작 스크립트는 Alembic 마이그레이션을 자동 적용합니다.

## 구조

```text
.
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── executor.py
│   │   ├── models.py
│   │   ├── pty_manager.py
│   │   └── modules/
│   ├── templates/
│   │   ├── services.yaml
│   │   └── runbooks.yaml
│   ├── alembic/
│   └── tests/
├── frontend/
│   └── src/
├── scripts/
└── docs/
```

- FastAPI는 API, 명령 실행, SSE, PTY와 파일 저장을 담당합니다.
- React, TanStack Query와 Vite는 로컬 UI와 서버 상태 동기화를 담당합니다.
- SQLite와 SQLAlchemy가 프로젝트 관계와 실행 이력을 저장합니다.
- `backend/templates/services.yaml`이 서비스별 명령과 위험도를 정의합니다.
- `backend/templates/runbooks.yaml`이 버전 관리되는 기본 방법론을 정의합니다.
- Alembic이 데이터베이스 스키마 변경을 관리합니다.

상세 설계는 [아키텍처](docs/ARCHITECTURE.md), 기능별 진행 상태는
[로드맵](docs/ROADMAP.md), 제품 용어는 [도메인 언어](CONTEXT.md), 변경 이력은
[작업 기록](docs/WORKLOG.md)을 참고하세요.

## 안전 경계

- API와 UI는 로컬 루프백에만 바인딩됩니다.
- 로컬 단일 사용자 도구이며 계정 및 역할 기반 접근 제어는 없습니다.
- 서버가 정적 템플릿과 검증된 변수를 이용해 명령을 다시 생성합니다.
- 일반 명령은 셸 문자열이 아니라 argv로 실행합니다.
- 위험한 명령과 PoC 실행은 별도의 사용자 승인 단계를 요구합니다.
- 실행 프로세스는 그룹 단위로 중단하며 앱 재시작 시 남은 실행 상태를 정리합니다.
- 업로드 크기, 파일 형식, 경로 순회와 symlink 이탈을 검증합니다.
- PoC 원본과 수정본을 분리하고 실행 직전 파일 해시를 다시 확인합니다.
- 자동 취약점 판정, 자동 공격 선택, 자동 셸 획득, 대규모 취약점 스캔, AI 분석과
  스푸핑은 제품 경계 밖입니다.

## 현재 제한사항

- Kali 데스크톱과 NetworkManager 사용을 전제로 한 기능이 있습니다.
- 다중 사용자 또는 원격 서버 배포를 위한 인증과 권한 분리는 없습니다.
- 서비스 식별과 실행 결과의 의미는 사용자가 검토해야 합니다.
- SearchSploit 후보는 취약성의 증거가 아니며 버전과 영향 조건을 직접 확인해야 합니다.
- 백업 복구는 자동화되어 있지 않습니다. 서버를 중지한 뒤 백업 ZIP의 DB와 산출물을
  해당 데이터 경로로 복원해야 합니다.
