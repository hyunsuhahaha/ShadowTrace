# OSCP Workspace Source Reference

> 이 문서는 2026-08-08의 working tree를 대상으로 작성한 코드 탐색 자료다(§10–13은
> 2026-08-09에 프런트엔드 화면별 구성·백엔드 모듈 파일 구성·이벤트버스/localStorage·
> CSS 맵을 추가하며 갱신). 제품 평가, 정책 해석, 설계 권고, 우선순위와 개선 제안은
> 포함하지 않는다. 동작 설명은 링크된 소스코드와 실행 스크립트에서 직접 확인할 수 있는
> 내용으로 한정한다. **새 파일/모듈/라우트/이벤트를 추가하거나 옮기거나 지웠다면 이
> 문서의 관련 절도 함께 갱신한다** — 그래야 다음 세션이 다시 전수조사를 하지 않는다.

## 1. 저장소 구성

| 경로 | 내용 |
|---|---|
| `backend/app` | FastAPI 애플리케이션, SQLAlchemy 모델, 실행 관리자와 기능별 router |
| `backend/alembic` | SQLite schema migration |
| `backend/templates` | 명령, Runbook, Service Intelligence, Credential Hunt YAML |
| `backend/tests` | Pytest 테스트 |
| `frontend/src` | React 화면, 상태 처리, API 호출과 Vitest 테스트 |
| `scripts` | 설치, 개발, 빌드, 테스트와 프로덕션 실행 스크립트 |
| `docs` | 정책, 아키텍처, 로드맵과 작업 기록 |

백엔드 패키지는 Python 3.11 이상을 요구하며 FastAPI, SQLAlchemy, Alembic, Pydantic,
httpx 등을 사용한다. 프런트엔드는 React 18, TanStack Query, TypeScript, Vite와 Vitest를
사용한다 ([`backend/pyproject.toml`](../backend/pyproject.toml),
[`frontend/package.json`](../frontend/package.json)).

## 2. 실행 구조

```text
Browser
  ├─ HTTP JSON / multipart
  ├─ EventSource (SSE)
  └─ WebSocket
          │
          ▼
FastAPI · 127.0.0.1:8000
  ├─ SQLAlchemy ── SQLite
  ├─ asyncio managers ── subprocess
  ├─ PTY / SSH tunnel / local proxy
  ├─ NetworkManager / tun0
  └─ workspace artifact files
```

### 개발 실행

`scripts/dev.sh`는 root 사용자로 실행되면 종료한다. 스크립트는 XDG 기반 환경 변수를
설정하고 migration을 적용한 뒤, backend launcher를 `sudo`로 시작하고 Vite를 현재
사용자로 실행한다. Vite는 `/api` 요청과 WebSocket을 기본
`http://127.0.0.1:8000`으로 전달한다
([`scripts/dev.sh`](../scripts/dev.sh),
[`frontend/vite.config.ts`](../frontend/vite.config.ts)).

`scripts/run-root-backend.sh`는 `OSCP_ALLOW_ROOT=1`과
`OSCP_BACKEND_BIND=127.0.0.1`을 설정하고 uvicorn을 시작한다. `setpriv` 호출은 GID와
supplementary group을 변경하며 UID 변경 옵션은 사용하지 않는다
([`scripts/run-root-backend.sh`](../scripts/run-root-backend.sh)).

### 프로덕션 실행

`scripts/start.sh`는 migration을 적용한 뒤 같은 backend launcher를 foreground로
실행한다. `frontend/dist`가 있으면 FastAPI가 `/assets`와 SPA fallback을 제공한다
([`scripts/start.sh`](../scripts/start.sh),
[`backend/app/main.py`](../backend/app/main.py)).

## 3. 애플리케이션 조립과 lifecycle

`backend/app/main.py`가 FastAPI 인스턴스를 만들고 다음 router들을 등록한다.

- Scan Center, Web Testing, Web Proxy
- Evidence, Findings, Reports, Directory
- Tunnels, Sessions, VPN, Hosts, System
- Exploit Research, Service Intelligence, Runbooks
- Post-Exploitation, Hash Cracking, Privilege-Escalation Analysis, Decoders
- Project/Target/Service core routes와 captured Executions

등록 순서와 import 위치는 [`backend/app/main.py`](../backend/app/main.py)에 있다.

lifespan 시작 시 다음 작업이 실행된다.

1. built-in Runbook을 SQLite에 반영한다.
2. 저장된 scan concurrency를 `ScanManager`에 적용한다.
3. 이전 프로세스의 미완료 scan을 `interrupted`로 변경하고 남은 파일을 등록한다.
4. orphaned privilege-escalation file server를 종료한다.
5. 미완료 Execution, Session, Tunnel, RemoteExecution과 HashCrackJob 상태를 정리한다.
6. 완료된 Execution과 Runbook Observation을 재조정한다.

종료 시 scan, captured execution, PTY, tunnel, post-exploitation, hash cracking, web proxy,
local exploit run과 privilege-escalation server의 종료 함수가 호출된다
([`backend/app/main.py`](../backend/app/main.py),
[`backend/app/modules/scan_center/manager.py`](../backend/app/modules/scan_center/manager.py)).

모든 `/api` 응답에는 `Cache-Control: no-store`가 설정된다. POST, PUT, PATCH, DELETE
응답은 method, path와 status code를 `AuditEvent`에 기록한다
([`backend/app/main.py`](../backend/app/main.py)).

## 4. 설정과 영속화

경로는 `backend/app/config.py`를 import할 때 결정되고 디렉터리가 생성된다.

| 환경 변수 | 기본값 | 저장 내용 |
|---|---|---|
| `OSCP_WORKSPACE_CONFIG` | `~/.config/oscp-workspace` | VPN 설정 |
| `OSCP_WORKSPACE_DATA` | `~/.local/share/oscp-workspace` | SQLite와 data files |
| `OSCP_WORKSPACE_STATE` | `~/.local/state/oscp-workspace` | PID와 backup |
| `OSCP_WORKSPACE_ROOT` | `~/OSCP-Workspace` | 프로젝트 산출물 |
| `OSCP_WORKSPACE_DB` | data directory의 `workspace.db` | SQLite database |

SQLite engine은 `check_same_thread=False`, 30초 connection timeout을 사용한다. connection
hook은 WAL journal mode와 30초 busy timeout을 설정한다
([`backend/app/config.py`](../backend/app/config.py),
[`backend/app/database.py`](../backend/app/database.py)).

`python -m app.migrations`는 database 상태에 따라 Alembic upgrade, metadata 기반 초기
생성 또는 legacy database adoption을 수행한다
([`backend/app/migrations.py`](../backend/app/migrations.py)).

## 5. 데이터 모델

전체 ORM model은 [`backend/app/models.py`](../backend/app/models.py)에 정의돼 있다.

```text
Project
 └─ Target
     ├─ Service
     ├─ ScanJob
     │   ├─ ScanArtifact
     │   ├─ HostObservation
     │   └─ ServiceObservation
     ├─ Execution
     ├─ InteractiveSession
     ├─ HttpRequest ── HttpExchange
     ├─ Evidence
     ├─ DirectoryObject / DirectoryRelation
     ├─ Tunnel
     ├─ ExploitResearch
     ├─ RemoteExecution
     └─ HashCrackJob

RunbookTemplate
 └─ RunbookTemplateVersion
     ├─ RunbookStepTemplate
     └─ RunbookInstance
         └─ RunbookStepInstance
             ├─ Evidence link
             ├─ Execution link
             ├─ Credential link
             └─ RunbookObservation

Finding
 ├─ FindingEvidence
 ├─ FindingAsset
 └─ FindingRetest
```

### Scan state와 현재 Service

`ServiceObservation`은 `scan_job_id`와 `target_id`를 포함한 scan별 관찰값이다. XML
ingest는 Nmap XML에 포함된 port state를 Observation으로 저장한다. `Service`는
`(target_id, port, protocol)` 조건으로 조회돼 갱신되며, 기존 row가 없을 때는 state가
`open`인 항목만 새로 생성된다
([`backend/app/modules/scan_center/service.py`](../backend/app/modules/scan_center/service.py)).

### 파일을 가리키는 model

`ScanArtifact`와 `Evidence`는 path, SHA-256, size와 original filename을 저장한다.
Execution, Session, Tunnel, HTTP Exchange, Exploit Research, RemoteExecution과
HashCrackJob도 관련 output path 또는 Evidence ID를 저장한다
([`backend/app/models.py`](../backend/app/models.py)).

### JSON 문자열 column

Service scripts, CPE, tags, Finding references, Runbook condition/transition, Credential service
names 등 여러 구조화 값은 `TEXT` column에 JSON 문자열로 저장된다
([`backend/app/models.py`](../backend/app/models.py),
[`backend/app/modules/runbooks/support.py`](../backend/app/modules/runbooks/support.py)).

## 6. 기능별 코드 위치와 동작

| 기능 | HTTP/interface 위치 | 실행 및 저장 위치 |
|---|---|---|
| Project, Target, Service | `modules/core/router.py` | `models.py`, workspace target directories |
| Scan | `modules/scan_center/router.py` | `service.py`, `manager.py`, scan artifacts |
| Captured command | `modules/executions/router.py` | `executor.py`, output files |
| Interactive session | `modules/sessions/router.py` | `pty_manager.py`, session logs |
| Web request | `modules/web_testing/router.py` | `HttpRequest`, `HttpExchange`, response files |
| Web proxy | `modules/web_proxy/router.py` | `manager.py`, mitmproxy addon |
| Evidence | `modules/evidence/router.py` | Evidence files와 ZIP export |
| Finding | `modules/findings/router.py` | Finding과 link tables |
| Report | `modules/reports/router.py` | Markdown, HTML, PDF, DOCX render/export |
| Directory | `modules/directory/router.py` | Directory object/relation rows |
| Runbook | `modules/runbooks/*_router.py` | `engine.py`, template/version/instance rows |
| Exploit Research | `modules/exploit_research/router.py` | original/working PoC와 execution records |
| Post-Exploitation | `modules/post_exploitation/router.py` | `manager.py`, sensitive Evidence |
| Hash Cracking | `modules/hash_cracking/router.py` | `manager.py`, hashcat files와 Evidence |
| VPN | `modules/vpn.py` | NetworkManager profile과 config directory |
| Tunnel | `modules/tunnels/router.py` | SSH process와 tunnel log |

위 표의 경로는 모두 [`backend/app/modules`](../backend/app/modules) 아래에 있다.

## 7. 주요 실행 흐름

### Scan

```text
POST /api/scans/preview
  → profile과 Target으로 command/argv 생성

POST /api/scans/run
  → ScanJob(status=queued) 저장
  → ScanManager.enqueue
  → subprocess 실행
  → stdout/stderr와 Nmap 또는 masscan 파일 저장
  → XML parse
  → HostObservation / ServiceObservation 저장
  → Target / Service 갱신
  → ScanArtifact / Evidence 저장
  → SSE로 출력과 terminal status 전송
```

profile 정의와 argv 생성은
[`backend/app/modules/scan_center/service.py`](../backend/app/modules/scan_center/service.py),
프로세스와 SSE 처리는
[`backend/app/modules/scan_center/manager.py`](../backend/app/modules/scan_center/manager.py),
endpoint는 [`backend/app/modules/scan_center/router.py`](../backend/app/modules/scan_center/router.py)에
있다.

### Captured Execution

```text
POST /api/executions
  → Target/Service와 template 조회
  → Catalog.render로 command와 argv 생성
  → Execution(status=queued) 저장
  → run_execution task 생성
  → subprocess 실행
  → stdout/stderr를 DB와 file에 저장
  → SSE로 출력과 terminal status 전송
```

명령 catalog는 [`backend/templates/services.yaml`](../backend/templates/services.yaml)에서
로드되며 matching과 rendering은 [`backend/app/templates.py`](../backend/app/templates.py),
endpoint는 [`backend/app/modules/executions/router.py`](../backend/app/modules/executions/router.py),
process 처리는 [`backend/app/executor.py`](../backend/app/executor.py)에 있다.

### Runbook

Template은 발행 시 Version과 ordered Step row로 복사된다. apply는 Version의 Step을
RunbookInstance와 RunbookStepInstance로 복사한다. Step update, approval, timer, Evidence,
Execution, Credential과 Observation 연결은 execution router가 처리한다. condition과
transition 결과 계산은 `engine.recompute`가 수행한다
([`backend/app/modules/runbooks/workflow_router.py`](../backend/app/modules/runbooks/workflow_router.py),
[`backend/app/modules/runbooks/execution_router.py`](../backend/app/modules/runbooks/execution_router.py),
[`backend/app/modules/runbooks/engine.py`](../backend/app/modules/runbooks/engine.py)).

### Post-Exploitation

prepare endpoint는 RemoteExecution과 approval token hash를 저장하고 token을 응답한다.
execute endpoint는 token을 확인하고 `prepared` 상태를 `running`으로 변경한 뒤 manager에
argv를 전달한다. manager는 stdout/stderr, timeout, cancel, 생성 파일과 Evidence 저장을
처리한다
([`backend/app/modules/post_exploitation/router.py`](../backend/app/modules/post_exploitation/router.py),
[`backend/app/modules/post_exploitation/manager.py`](../backend/app/modules/post_exploitation/manager.py)).

## 8. 프로세스 상태

문자열 상태값은 model column과 router/manager에서 관리한다. 주요 흐름은 다음과 같다.

| 대상 | 생성 상태 | 실행 상태 | 종료 상태 |
|---|---|---|---|
| ScanJob | `queued`, `processing` | `running` | `completed`, `failed`, `stopped`, `interrupted` |
| Execution | `queued` | `running` | `completed`, `failed`, `no_response`, `stopped`, `interrupted` |
| InteractiveSession | `ready` | `running` | `completed`, `failed`, `stopped`, `interrupted` |
| Tunnel | `ready` | `running`, `stopping` | `completed`, `failed`, `stopped`, `interrupted` |
| RemoteExecution | `prepared` | `running` | `completed`, `failed`, `timed_out`, `cancelled` |
| HashCrackJob | `prepared` | `running` | `completed`, `failed`, `cancelled` |

Scan, Execution, RemoteExecution과 HashCrackJob의 SSE endpoint는 메모리 queue에서 live
event를 읽는다. Scan, RemoteExecution과 HashCrackJob endpoint는 연결 시 DB 상태와 저장된
output 일부를 snapshot으로 보낸다. Execution endpoint는 queue event와 heartbeat를 보내며
저장된 최종 출력은 별도 output endpoint가 제공한다
([`backend/app/modules/scan_center/router.py`](../backend/app/modules/scan_center/router.py),
[`backend/app/modules/executions/router.py`](../backend/app/modules/executions/router.py),
[`backend/app/modules/post_exploitation/router.py`](../backend/app/modules/post_exploitation/router.py),
[`backend/app/modules/hash_cracking/router.py`](../backend/app/modules/hash_cracking/router.py)).

## 9. 프런트엔드

`frontend/src/main.tsx`가 `QueryClientProvider`와 `Root`를 mount한다. `Root`는
`location.hash`를 파싱하고 화면을 lazy import한다. 별도 routing package는 사용하지
않는다
([`frontend/src/main.tsx`](../frontend/src/main.tsx),
[`frontend/src/Root.tsx`](../frontend/src/Root.tsx)).

`AppShell`은 navigation, 현재 Project/Target 표시, VPN, Metasploit target state와 command
palette를 제공한다. 선택 상태와 panel 크기 일부는 `localStorage`에 저장되고 Project,
Target과 Service 이동은 `oscp-project-change`, `oscp-target-change`, `oscp-service-nav`
DOM custom event도 사용한다
([`frontend/src/AppShell.tsx`](../frontend/src/AppShell.tsx),
[`frontend/src/pendingServiceNav.ts`](../frontend/src/pendingServiceNav.ts)).

서버 상태는 각 화면의 TanStack Query key로 조회된다. 공용 `api` 함수는 `/api` prefix,
non-2xx 오류 처리와 JSON decode를 제공한다
([`frontend/src/api.ts`](../frontend/src/api.ts),
[`frontend/src/useEnumerationQueries.ts`](../frontend/src/useEnumerationQueries.ts)).

실시간 연결 위치는 다음과 같다.

- Scan: `ScanCenter.tsx`
- Captured Execution: `App.tsx`, `ToolsWorkspace.tsx`
- Post-Exploitation: `PostExploitationWorkspace.tsx`, `App.tsx`
- Hash Cracking: `HashCrackingWorkspace.tsx`
- PTY: `InteractiveTerminal.tsx`

## 10. 프런트엔드 화면별 구성

`frontend/src/Root.tsx`의 hash route와 각 화면이 조합하는 하위 컴포넌트다. 첫 로드시
`sessionStorage["oscp-home-shown"]`이 없으면 `#graph`로 강제 이동한다(같은 브라우저
세션 내 이후 이동에는 적용되지 않음). 프로젝트가 바뀌면(`oscp-project-change`)
`Root.tsx`가 `projectRevision`을 증가시켜 `<AppShell key={projectRevision}>` 전체를
리마운트한다 — 프로젝트별로 남아있던 화면 상태를 지우는 방식이다.

| Hash | 컴포넌트 파일 |
|---|---|
| `#enumeration` | `App.tsx` (Service Enumeration) — "← Scan Center" 뒤로가기 링크와 함께 렌더 |
| `#web` (`#web/<tab>`) | `WebWorkspace.tsx` |
| `#evidence` | `EvidenceWorkspace.tsx` |
| `#directory` | `DirectoryWorkspace.tsx` |
| `#sessions` | `SessionWorkspace.tsx` |
| `#reports` | `ReportWorkspace.tsx` |
| `#operations` | `OperationsWorkspace.tsx` |
| `#exploit-research` | `ExploitResearchWorkspace.tsx` |
| `#runbooks` | `RunbookWorkspace.tsx` |
| `#post-exploitation` | `PostExploitationWorkspace.tsx` |
| `#hash-cracking` | `HashCrackingWorkspace.tsx` |
| `#tools` | `ToolsWorkspace.tsx` |
| `#graph`, `#dashboard` | `features/graph/GraphWorkspace.tsx` (기본 홈 라우트) |
| 그 외 / 빈 hash | `ScanCenter.tsx` (default case) |

### 10.1 `App.tsx` — Service Enumeration (`#enumeration`)

Project → Target → Service를 고른 뒤, 검토된 명령 템플릿(nmap 후속 조사, 자격증명
점검, AD 공격, 디코더)을 실행하고 SSE 터미널과 실행 이력을 본다. `GraphWorkspace`가
service 노드 선택 시 자신을 그대로 embed해서 재사용한다(`embedded` prop).
API: `/projects`, `/targets`, `/targets/{id}/services`, `/targets/{id}/hostname`,
`/services/{id}/commands`, `/services/{id}/intelligence`, `/services/{id}`,
`/targets/{id}/identity-commands`, `/executions*`(SSE 포함), `/interactive-sessions*`,
`/hosts/sync`, `/system/status`, `/privesc-server/status`, `/evidence/upload`,
`/runbooks/credentials`, `/post-exploitation/prepare` 등.
보조 모듈: `enumerationModel.ts`, `serviceIntel.ts`, `serviceGuidance.ts`,
`credentialAudit.ts`/`credentialAuditResult.ts`, `useCredentialStore.ts`,
`useEnumerationQueries.ts`.

| 하위 컴포넌트 | 역할 |
|---|---|
| `ServiceIntelligencePanel.tsx` | 선택 서비스의 "조사 단계" 아코디언, 단계별 명령 실행과 화면 최상단 결과 모달(Backdrop/×/Escape로 닫기) |
| `FuzzingPanel.tsx` | feroxbuster 디렉터리/파일 퍼징 + 결과 필터 테이블 |
| `VhostFuzzPanel.tsx` | ffuf Host 헤더 기반 virtual-host 퍼징 |
| `DnsSubdomainPanel.tsx` | gobuster DNS 서브도메인 브루트포스 |
| `ParamFuzzPanel.tsx` | ffuf GET 파라미터명 퍼징 |
| `LinkExtractPanel.tsx` | 단일 요청 HTML href/src/action 추출(재귀 없음) |
| `S3BucketPanel.tsx` | awscli 기반 S3/MinIO 버킷·오브젝트 목록, PHP webshell 업로드 |
| `CloudEnumPanel.tsx` | `cloud_enum`으로 AWS/Azure/GCP 네이밍 키워드 검색 |
| `KerbruteEnumPanel.tsx` | `kerbrute userenum` Kerberos 사용자명 열거 |
| `AsrepRoastPanel.tsx` | impacket `GetNPUsers` AS-REP roasting |
| `PasswordSprayPanel.tsx` | NetExec 패스워드 스프레이(락아웃 정책 경고 포함) |
| `DomainDominancePanel.tsx` | BloodHound 수집, DCSync, gMSA/LAPS 비밀번호 조회 |
| `SilverTicketPanel.tsx` | impacket `ticketer.py` Silver Ticket 위조 |
| `ConstrainedDelegationPanel.tsx` | impacket `getST.py` (S4U2Self/S4U2Proxy) |
| `CiscoType7Decoder.tsx` | Cisco Type 7 비밀번호 클라이언트측 XOR 복호화 |
| `GppCpasswordDecoder.tsx` | GPP `cpassword` 복호화(AES, 고정 키) |
| `VncPasswordDecoder.tsx` | VNC DES-ECB 저장 비밀번호 복호화(백엔드 왕복) |
| `RoundcubeDesDecoder.tsx` | Roundcube 세션 테이블 비밀번호(3DES-EDE3-CBC) 복호화 |
| `DpapiDecoderPanel.tsx` | DPAPI masterkey→key, credential blob→평문 2단계 복호화 |
| `PuttyKeyConverter.tsx` | `.ppk` → OpenSSH 키 변환(`puttygen`) |
| `PypykatzLsassPanel.tsx` | lsass 덤프 업로드 후 `pypykatz` 실행 |
| `RecycleBinDecoder.tsx` | `$RECYCLE.BIN`의 `$I` 인덱스 파싱 |
| `GiteaHashFormatter.tsx` | Gitea `passwd`/`salt` → hashcat `-m 10900` 포맷 변환 |
| `ReverseShellPanel.tsx` | 리버스쉘 페이로드 생성, webshell 다운로드, 안정화 치트시트 |
| `ChiselPivotPanel.tsx` | chisel server/client 명령 생성(SOCKS·단일 포트) |
| `ResponderPanel.tsx` | Kali 데스크톱 터미널에서 Responder 시작, 캡처 폴링 |
| `SmbShareResults.tsx` | SMB 공유 목록, 연결·재귀 목록, 첫 공유 자동 스파이더 |
| `ServiceList.tsx` | 대상의 서비스 목록(좌측 레일) |
| `ExecutionHistory.tsx` | 실행 목록/상세 탭; `OutputColumnExtractor.tsx`(컬럼 추출·Evidence 저장)를 포함 |
| `ExecutionMonitor.tsx` | 백그라운드 실행 중인 모든 명령을 보여주는 플로팅 패널 |
| `ServiceWorkspace.tsx` | 서비스별 메모/태그/제품/버전 편집 + 체크리스트 |
| `CommandReviewModal.tsx` | 실행 전 검토 모달(sudo, 출력 파일명, 위험 경고) — `ToolsWorkspace.tsx`도 재사용 |
| `EnumerationScope.tsx` | 상단 nav: project/target 선택·생성, Nmap XML 가져오기, 누락 도구 배너; `VpnControl.tsx` 포함 |
| `CredentialAuditPanel.tsx` | 프로토콜별 자격증명 점검 명령(브루트/빈 비밀번호/익명) |
| `ServiceDashboard.tsx` | "선택한 포트 요약" — 알려진/미지 사실, NSE 관찰값, 빠른 점검 |
| `InvestigationCommandList.tsx` | 전용 패널이 없을 때의 일반 검토 명령 카드 목록 |
| `ManualGuidance.tsx` | 수동 로그인이 필요한 서비스용 정적 가이드 + 계정 후보 |
| `JobStatus.tsx` | 단일 실행 상태 배너(경과시간, 프로세스 생존, stale 경고) |
| `CredentialStoreForm.tsx` | `useCredentialStore` 훅과 연결된 자격증명 입력/저장 목록 |
| `NetexecOutcome.tsx` | NetExec 성공 후 psexec/wmiexec/evil-winrm 등 다음 행동 제안 |
| `PrivescSessionPanel.tsx` | LinPEAS/WinPEAS/pspy 파일 서버 토글, 세션 로그에서 NetNTLMv2 해시 폴링 |
| `LiveOutputPanel.tsx` | 실시간 출력 패널(`D\|`/`F\|` 태그 출력은 파일 트리로 렌더) |

### 10.2 `ScanCenter.tsx` — 기본(unmatched) 라우트

Nmap/masscan 스캔: 대상 선택/생성 → 프로필 선택(전체 TCP/UDP/선택 포트/masscan) →
Scope 검토 → 대기열 등록 → SSE 출력. XML 가져오기, 스캔 이력/diff 비교, 산출물
다운로드(XML/CSV/JSON)도 담당. `GraphWorkspace`가 project-root/host 노드 선택 시
`embedded` prop으로 재사용한다.
API: `/projects`, `/targets`(+`/targets/ensure`), `/scans/profiles`, `/scans*`(CRUD,
observations, artifacts, automation, events SSE, stop, rerun, export, compare, preview,
run, import), `/vpn/status`.

| 하위 컴포넌트/모듈 | 역할 |
|---|---|
| `ScanToolPicker.tsx` | nmap/masscan 선택; VPN `tun` 인터페이스에서는 masscan 비활성 |
| `ScanProfileComposer.tsx` | 대상 IP/이름 입력, 프로필 드롭다운, 포트 입력, XML 가져오기, 명령 미리보기, "스캔 검토" 버튼 |
| `ScanJobStatus.tsx` | 선택 스캔의 실시간 상태 카드 + 완료 후 자동화 배너(증적/finding 수, 자동 연계 상세 스캔) |
| `ScanHistoryPanel.tsx` | 스캔 큐/이력 목록(검색·상태 필터), 중지/재실행/삭제, base 비교 |
| `scanCenterModel.ts` | 공용 타입(`Project`/`Target`/`Scan`/`Profile`/`Obs`/`Artifact`/`Automation`), 프로필 라벨/그룹 표, `elapsed()`/`bytes()`, `syncSelectedProject()` |
| `VpnControl.tsx` | VPN 전역 위젯(`.ovpn` 업로드, 검토+연결, 해제, DNS 지정) — `AppShell.tsx`/`EnumerationScope.tsx`도 사용 |

### 10.3 `WebWorkspace.tsx` — Web Testing (`#web`, `#web/<tab>`)

수동 HTTP 요청/응답 워크벤치: 요청 작성/저장/전송, 변수 치환 재전송, 응답 diff, Intruder류
퍼저, 페이로드 레퍼런스, 패시브 프록시 캡처.
API: `/targets`, `/web/requests*`(CRUD, duplicate, exchanges, send), `/web/exchanges/{id}/body`,
`/web/exchanges/{id}/compare/{id2}`, `/vpn/status`.

| 하위 컴포넌트/모듈 | 역할 |
|---|---|
| `IntruderPanel.tsx` | Intruder 클론: sniper/battering-ram/pitchfork/cluster-bomb, payload position, match/filter, 저장 후보군, `/web/intruder/{runId}` 실행 제어 |
| `SqlPayloadReference.tsx` | SQLi 페이로드 치트시트(복사/Intruder 전송, 자동 실행 없음) |
| `LfiPayloadReference.tsx` | LFI/경로 순회 페이로드 치트시트, tun0 IP 자동 채움 |
| `Log4ShellPayloadReference.tsx` | CVE-2021-44228 JNDI probe 카탈로그 |
| `ProxyPanel.tsx` | mitmproxy 패시브 캡처(시작/중지, CA 인증서 다운로드), 클라우드 지문 배지 |
| `murmurHash.ts` / `curlImport.ts` | Shodan favicon 해시 계산 / cURL → 요청 초안 파서(비-컴포넌트 헬퍼) |

### 10.4 `EvidenceWorkspace.tsx` — 증적 (`#evidence`)

대상별 파일/스크린샷/플래그/마크다운 업로드(드래그앤드롭), 메타데이터 편집(제목,
사용자명/호스트명/획득 권한, 민감도, 보고서 포함 여부, 태그), Exploit Research 후보
연결, 선택적 ZIP export. 하위 컴포넌트 없음.
API: `/targets`, `/evidence?target_id=`, `/evidence/{id}`, `/evidence/upload`,
`/evidence/export`, `/projects/{id}/exploit-research?target_id=`.

### 10.5 `DirectoryWorkspace.tsx` — AD 정보 (`#directory`)

AD 객체(사용자/그룹/컴퓨터/공유/SPN/세션/신뢰/자격증명 출처)를 수동 입력 또는
CSV/JSON으로 가져오고, "관찰된" 관계(예: `observed_member_of`)를 연결한다. 하위
컴포넌트 없음.
API: `/projects`, `/directory/objects*`, `/directory/objects/import`, `/directory/relations*`.

### 10.6 `SessionWorkspace.tsx` — Tunnel 및 세션 (`#sessions`)

SSH 터널(local/remote/dynamic) 관리와 다른 화면에서 열린 모든 대화형 세션 목록,
연결별 로그 다운로드/중지. 하위 컴포넌트 없음.
API: `/targets`, `/tunnels*`, `/interactive-sessions*`, `/{kind}/{id}/stop`.

### 10.7 `ReportWorkspace.tsx` — 보고서 (`#reports`)

3탭 허브: Findings(`FindingWorkspace`에 위임), Finding 라이브러리(`FindingTemplateManager`에
위임), 보고서 생성(자체 마크다운 에디터 — Evidence/Exploit Research 링크, 실시간 HTML
미리보기, Markdown/HTML/PDF/DOCX export).
API: `/projects`, `/reports*`, `/reports/{id}/export`, `/evidence?project_id=`,
`/projects/{id}/exploit-research?limit=`.

| 하위 컴포넌트 | 역할 |
|---|---|
| `FindingWorkspace.tsx` | Finding 전체 에디터: 트리아지 큐, CVSS 3.1 벡터 빌더, 대상/서비스 다중 선택, Evidence 링크 레일(`EvidenceImageEditor.tsx` 오픈), 재검증 타임라인, 템플릿 적용 |
| `FindingTemplateManager.tsx` | 재사용 Finding 템플릿 라이브러리 CRUD, JSON/YAML export, 가져오기, 복제 |
| `EvidenceImageEditor.tsx` (손자) | 스크린샷 비파괴 주석 편집기(crop/box/arrow/text/mosaic), 버전 이미지 저장 |

### 10.8 `OperationsWorkspace.tsx` — 검색·감사·백업 (`#operations`)

대상/서비스/증적/AD/보고서 전역 검색, 전체 DB 백업 생성/다운로드, 스캔 동시성 설정,
읽기 전용 로컬 변경 감사 로그. 하위 컴포넌트 없음.
API: `/operations/search`, `/operations/backups*`, `/operations/audit`, `/scans/settings`.

### 10.9 `ExploitResearchWorkspace.tsx` — Exploit Research (`#exploit-research`)

서비스/대상 단위 공개 익스플로잇 조사·수동 검증 추적: SearchSploit/WES-NG/LES 실행,
후보 등록, 로컬 PoC 가져오기/diff/편집, 변수 수정 추적, approve→execute 1회 로컬
샌드박스 실행(해시 고정, 타임아웃) 또는 수동 실행 결과 기록. 자동 익스플로잇 없음(정책
배너 표시).
API: `/projects`, `/targets`, `/services/{id}/searchsploit`, `/targets/{id}/wes-ng`,
`/targets/{id}/les`, `/exploit-research/*`, `/projects/{id}/exploit-research*`,
`/evidence?project_id=`, `/interactive-sessions/manual`.

| 하위 컴포넌트 | 역할 |
|---|---|
| `InteractiveTerminal.tsx` | xterm.js + WebSocket PTY 뷰어; `PrivescSessionPanel.tsx`(App.tsx의 손자)도 사용 |

### 10.10 `RunbookWorkspace.tsx` — Runbooks (`#runbooks`)

Template Library(내장+사용자 작성, 조건 분기, 버저닝, 복제/export/import/보관)와
Instance 실행 화면(단계별 상태/결과/메모, 위험 단계 승인 게이트, 타이머, Evidence/
Execution/Credential 연결, 관찰값→Finding 승격, 활동 타임라인). 별도 하위 파일 없이
Step 카드 UI(`StepEditor`)가 같은 파일에 정의됨.
API: `/projects`, `/targets*`, `/runbooks/templates*`, `/runbooks/instances*`,
`/runbooks/recommendations/*`, `/runbooks/steps/{id}*`, `/runbooks/credentials*`,
`/runbooks/summary`, `/runbooks/findings*`, `/evidence?project_id=`, `/executions?target_id=`.

### 10.11 `PostExploitationWorkspace.tsx` — Post-Exploitation (`#post-exploitation`)

저장된 자격증명 + 카탈로그 명령(설정파일 비밀번호, DB 자격증명, 백업, 브라우저/환경
변수 시크릿, 다른 사용자 홈, Windows Credential Manager, SSH 키, 노트/로그, privesc 후
해시, BloodHound 수집, 폴더/파일 트리)을 골라 SSH/wmiexec/secretsdump/bloodhound-python/
nxc로 approve→execute 실행, 출력 스트리밍(트리 명령은 파일 트리 렌더). LinPEAS/SUID
분석기도 포함, Finding으로 승격 가능.
API: `/projects`, `/targets`, `/runbooks/credentials?project_id=`,
`/post-exploitation/catalog`, `/post-exploitation*`, `/targets/{id}/linpeas`,
`/targets/{id}/suid-scan`, `/findings`.

| 하위 컴포넌트 | 역할 |
|---|---|
| `fileTree.tsx` | `D\|`/`F\|` 태그 라인 → 접기 가능 파일 트리 파서/렌더러; `LiveOutputPanel.tsx`/`NetexecOutcome.tsx`(App.tsx의 손자)도 사용 |

### 10.12 `HashCrackingWorkspace.tsx` — Hash Cracking (`#hash-cracking`)

해시 붙여넣기(정규식 카탈로그로 모드 자동 감지) 또는 zip 업로드(`zip2john`), 공격
모드(straight/combination/mask/hybrid) 선택, 실행+실시간 출력, 크랙된 평문을
Credential Store로 승격. `oscp-workspace-hash-*` localStorage 키로 App.tsx의
Kerberoast/AS-REP/DCSync/NTLM 해시 "크래킹으로 보내기" 버튼과 연결. 하위 컴포넌트
없음(리사이즈 패널 로직은 인라인).
API: `/projects`, `/targets`, `/hash-cracking/catalog`, `/hash-cracking*`,
`/hash-cracking/{id}/promote`, `/hash-cracking/zip2john`.

### 10.13 `ToolsWorkspace.tsx` — Tools (`#tools`)

자동 서비스 분류에 의존하지 않는 전체 명령 카탈로그(111개) 탐색 — Nmap이 놓쳤거나
오분류한 서비스(예: WinRM을 http로 인식)를 위한 대안 경로. 대상 선택 → 서비스 또는
수동 포트/스킴 입력 → 변수 채움 → 검토 → 실행(스트리밍 또는 데스크톱 대화형 세션).
API: `/projects`, `/targets`, `/targets/{id}/services`, `/tool-catalog`,
`/executions*`, `/interactive-sessions*`.
하위 컴포넌트: `CommandReviewModal.tsx`(App.tsx와 공유).

### 10.14 `features/graph/GraphWorkspace.tsx` — Progress Graph (`#graph`, 기본 홈)

프로젝트 전체를 보여주는 허브: project-root → host → service/finding/technique/credential
노드의 force-directed Canvas 2D 그래프(nmap target/service에서 자동 동기화 + 수동 추가
노드/엣지), Outline(트리) 뷰 대안, 노드 상태 편집, 숨김 토글, 우측 상세 패널은 일반
Inspector(하위 노드 추가 폼) 또는 — project-root/host 노드
선택 시 `ScanCenter.tsx`를, service 노드 선택 시 `App.tsx`를 `embedded` prop으로 그대로
끼워넣는다(`lazy(() => import(...))`, 자체 chrome는 숨김). Execution에서 투영된 모든
technique 노드는 원본 실행 상태·대상/서비스·명령·stdout/stderr/error를 표시한다.
`http-link-extract`는 여기에 유형순 링크 목록, Evidence 파생 저장과 Web Testing Request
handoff를 추가로 제공하며, handoff 시 그래프를 벗어나지 않고 우측 GraphRequestPanel에서
편집·저장·전송·응답 검토까지 수행한다. GraphRequestPanel은 `/vpn/status`의 tun0 IPv4를
UNC 경로로 URL 커서 또는 `page=` 값에 삽입하는 Responder IP 단축 기능도 제공한다.
Finding과 credential 작업도 라우트를 바꾸지 않는다. Finding은 `ReportWorkspace.tsx`,
credential은 `HashCrackingWorkspace.tsx`와 `PostExploitationWorkspace.tsx`를 각각
`embedded` 인터페이스로 우측 패널에 lazy-load한다. 이 어댑터는 프로젝트·대상·해시·모드·
credential을 초기값으로 넘기되 원본 폼, 실행 터미널, 결과, Evidence 저장, 이력 기능을
그대로 재사용한다. 패널 폭이 좁으면 container query로 이력을 아래로 재배치하며 숨기지 않는다.
Responder session 노드는 대상의 캡처 로그를
4초마다 조회해 해시 보기·복사·Credential 저장을 제공한다. `credential` 노드는 기본적으로
Post-Exploitation handoff를 제공하고, `credType=hash`이면 실제 secret/target을 채우는 Hash
Cracking handoff도 함께 제공한다. 실행 중인 스캔은 host 노드, 실행 중인 명령·세션은
technique 노드의 `meta.activity`에 투영되어 Canvas에서 녹색 레이더 파동·스윕·엣지
패킷으로 표시되며 종료 시 제거된다. 데스크톱 Responder는 PID가 살아 있는 동안 별도의
빨간 `LISTENING` 레이더로 표시되고 2초 동기화로 창 종료를 반영한다. Responder는 대상
Host의 자식이 아니라 `Kali Operator · <tun0 IP>` 아래 `runs`로 배치되고, 대상에는 방향성
비구조 엣지 `captures-from`(`AUTH CAPTURE`)으로 연결된다. 프로젝트가 없으면 "start"
합성 노드로 프로젝트 생성 유도. GraphCanvas/OutlineView/Row/Inspector/AddNodeForm/
OnboardingPane 등 모든 UI가 단일 파일에 인라인으로 정의되며 동작 회귀 테스트는
`features/graph/GraphWorkspace.test.tsx`에 있다.
API: `/projects`(POST), `/projects/{id}/graph`, `/projects/{id}/graph/sync`(POST, idempotent),
`/projects/{id}/graph/tree`, `/projects/{id}/graph/nodes`(POST), `/projects/{id}/graph/edges`(POST),
`/graph/nodes/{id}`(PATCH), `/executions/{id}/output`, `/executions/{id}/derive`,
`/targets`, `/targets/{id}/services`.

### 10.15 인프라/공용 파일 (특정 워크스페이스에 속하지 않음)

`Root.tsx`(해시 라우터), `AppShell.tsx`(영속 헤더/nav/프로젝트 선택 shell —
`VpnControl.tsx`, `CommandPalette.tsx`, `MetasploitLock.tsx` 포함), `CommandPalette.tsx`
(Ctrl-K 전역 팔레트, `commandPaletteIndex.ts`로 인덱싱), `MetasploitLock.tsx`(단일 대상
Metasploit 잠금 배너), `ui.tsx`(Badge/Button/Card/EmptyState/ErrorState/LoadingState/
PageHeader/statusCopy), `api.ts`(fetch 래퍼), `main.tsx`(Vite entry).

`frontend/src/*.tsx` 전수 조사 결과 고아(아무 워크스페이스에서도 import하지 않는)
컴포넌트는 없다 — 모든 top-level 컴포넌트가 14개 워크스페이스 중 하나의 직계 자식이거나
손자(자식의 자식)다.

## 11. 백엔드 모듈 파일 구성

`backend/app/` 최상위 파일(모듈 디렉터리 밖):

| 파일 | 줄수 | 역할 |
|---|---|---|
| `main.py` | 160 | FastAPI 앱 조립, 모든 router 등록, lifespan, root 실행 차단, 감사 로깅 미들웨어, SPA static fallback |
| `database.py` | 59 | SQLAlchemy 엔진/세션, WAL, `get_db`, `ensure_compatible_schema()`(pre-Alembic 로컬 DB용 ALTER TABLE) |
| `config.py` | 12 | XDG 경로 상수, `OSCP_WORKSPACE_*` 환경변수, import 시 디렉터리 생성 |
| `models.py` | 805 | 전체 SQLAlchemy ORM 모델(모듈별 분리 없이 단일 파일) |
| `schemas.py` | 412 | 여러 모듈이 공유하는 Pydantic 스키마(모듈 전용 스키마는 각 모듈의 `schemas.py`에 별도) |
| `migrations.py` | 222 | Alembic upgrade 래핑 + pre-Alembic DB를 `RUNBOOK_STAGES` 매핑으로 채택 |
| `executor.py` | 224 | 허용 목록 기반 shell 명령 실행/스트리밍/중지 핵심 엔진, 리다이렉트로 hostname 자동 채움 |
| `product_policy.py` | 32 | 허용/금지 제품 정책(자동 취약점 판정·자동 공격·spoofing 금지 등) 정적 선언, UI 정책 배너용 |
| `templates.py` | 89 | `templates/services.yaml` → `Catalog`, `{token}` 치환 허용 토큰 정의 |
| `pty_manager.py` | 187 | WebSocket 대화형 PTY 세션 관리, `/proc` 순회로 프로세스 트리 종료 |
| `time.py` | 6 | `utcnow()` 헬퍼 |
| `nmap_parser.py` | 52 | Nmap/masscan XML → host/service dict, `defusedxml` 사용 |
| `cloud_storage_probe.py` | 166 | AWS S3/Azure Blob/GCS/S3-호환(MinIO) 지문 판별 |
| `docker_tree.py` / `ftp_tree.py` / `imap_tree.py` / `ldap_tree.py` / `mongodb_tree.py` | 각 59/94/73/92/57 | 무인증 Docker/FTP/IMAP/LDAP/MongoDB 목록 조회 CLI 스크립트(`D\|`/`F\|` 태그 출력) |
| `ntlm_probe.py` | 121 | HTTP(S) NTLM Type1/Type2 핸드셰이크로 도메인/컴퓨터명 노출 |
| `redirect_probe.py` | 90 | HTTP 3xx `Location`/`<meta refresh>`로 canonical hostname 탐지 |
| `rpc_probe.py` | 144 | impacket 기반 MSRPC endpoint mapper 열거 + bind-only 체크 |
| `svn_dump.py` | 88 | 노출된 `.svn` working copy(`wc.db`)에서 소스 트리 복원 |
| `webdav_tree.py` | 106 | WebDAV `PROPFIND Depth:1` 재귀 목록 |

`*_tree.py`/`*_probe.py`/`svn_dump.py`/`nmap_parser.py`는 라이브러리로 import되지 않고
템플릿 카탈로그가 subprocess로 직접 실행하는 독립 CLI 스크립트다.

`backend/app/modules/`에는 21개 디렉터리와 4개의 독립 라우터 파일이 있다(`ls`로 확인,
`docs/ARCHITECTURE.md`의 모듈 표와 이름이 다른 경우가 있음 — 아래 11.x 참고).

| 모듈 | 책임 | 라우트 prefix | 최대 파일(줄수) |
|---|---|---|---|
| `core` | Project/Target/Service CRUD, Metasploit 단일 대상 잠금, 삭제 cascade | (inline, 예: `/api/projects`) | `router.py`(403) |
| `decoders` | DPAPI/PuTTY/Roundcube/VNC 오프라인 복호화 | `/api/decoders` | `router.py`(187) |
| `directory` | AD 객체/관계 CRUD, CSV 가져오기 | `/api/directory` | `router.py`(137) |
| `evidence` | 증적 업로드/목록/다운로드/삭제, SHA-256, zip export | `/api/evidence` | `router.py`(157) |
| `executions` | 사용자 확인 명령 실행 API(엔진은 `executor.py`) | (inline, `/api/executions`) | `router.py`(208) |
| `exploit_research` | 익스플로잇 후보/PoC/WES-NG·LES/로컬 실행 lifecycle | (inline) | `router.py`(885, 백엔드 최대 파일) |
| `findings` | Finding CRUD, CVSS, 재검증, 증적 링크, 이미지 주석, 템플릿 | `/api`(tags=Findings) | `router.py`(403) |
| `graph` | Progress Graph 트리/DAG, spec: `docs/SPEC_GRAPH_TRACKER.md` | `/api`(tags=Graph) | `service.py`(371) |
| `hash_cracking` | hashcat job lifecycle, 모드 자동 감지, 크랙 결과 → Credential 승격 | `/api/hash-cracking` | `router.py`(276) |
| `operations` | 전역 검색, DB/프로젝트 export/backup | `/api/operations` | `router.py`(169) |
| `post_exploitation` | 자격증명 기반 원격 명령 실행(impacket/nxc/evil-winrm류) | `/api/post-exploitation` | `manager.py`(180) |
| `privesc_analysis` | LinPEAS 파싱/하이라이트, SUID→GTFOBins 매칭 | (inline) | `router.py`(113) |
| `reports` | DOCX(`python-docx`)/PDF(`weasyprint`) 보고서 생성 | `/api/reports` | `router.py`(471) |
| `runbooks` | 버전 방법론 템플릿/인스턴스/단계 실행 엔진 | `/api/runbooks`(3개 router 공유) | `support.py`(465) |
| `scan_center` | Nmap/masscan 프로필/job queue/원본 파일/파싱/비교 | `/api/scans` | `service.py`(358) |
| `service_intelligence` | CPE/제품 매칭, 서비스 가이드, runbook 추천 연계 | (inline) | `catalog.py`(401) |
| `sessions` | 대화형 PTY lifecycle, RDP/VNC 데스크톱 실행, WS 릴레이 | (inline) | `router.py`(347) |
| `tunnels` | SSH 등 포트 포워딩/피벗 터널 lifecycle | `/api/tunnels` | `router.py`(149) |
| `web_proxy` | mitmproxy 기반 단일 대상 IP 스코프 가로채기 프록시 | `/api/web/proxy` | `router.py`(125) |
| `web_testing` | 수동 HTTP 요청/응답 워크벤치, Intruder 배치 전송 | `/api/web` | `router.py`(452) |

독립 라우터 파일(디렉터리가 아님, `modules/` 바로 아래):

| 파일 | 역할 | 라우트 prefix |
|---|---|---|
| `modules/hosts.py` | `/etc/hosts`의 마커 구분 블록 관리(대상 hostname 해석), `core.router`의 삭제 cascade에서 호출 | `/api/hosts` |
| `modules/system.py` | 필수 CLI 도구 설치 여부 + VPN 상태 | 단일 route `/api/system/status` |
| `modules/vpn.py` | OpenVPN 설정 업로드/연결/해제(`nmcli`), 위험한 `.ovpn` 지시어 제거 | `/api/vpn` |
| `modules/privesc_server.py` | `tun0`에만 바인딩되는 별도 `http.server` subprocess로 LinPEAS/WinPEAS/pspy 제공 | `/api/privesc-server` |

`scan_center/service.py`의 `_safe()`와 `import_xml`/`ingest_xml`은 core, evidence,
exploit_research, findings, hash_cracking, post_exploitation, privesc_analysis, tunnels,
web_testing 등 다른 모듈에서도 널리 import된다 — 사실상 자기 도메인을 넘어선 공용
유틸리티 허브다.

### 11.1 `docs/ARCHITECTURE.md` 모듈 표와의 차이

`docs/ARCHITECTURE.md`는 `core`/`scans`/`enumeration`/`runbooks`/`web`/`directory`/
`sessions`/`evidence`/`reports` 9개 개념적 모듈로 설명하지만, 실제 `backend/app/modules/`
폴더 이름과 개수는 다르다(작성 시점 이후 스캐폴딩이 늘어난 것으로 보인다).

- `scans` → 실제 폴더명은 `scan_center`(이름만 다름, 범위는 동일).
- `enumeration`(서비스 관찰값/정적 명령/실행) → 지금은 `service_intelligence`(서비스
  관찰/카탈로그) + `executions`(실행 router) + 최상위 `templates.py`(명령 카탈로그) 3곳으로
  분리됨.
- `web` → `web_testing`(문서의 설명과 일치) + 문서에 없는 `web_proxy`(mitmproxy 프록시)가
  추가됨.
- `sessions` → 문서는 "터널과 PTY 세션"을 한 행으로 묶지만 실제로는 `sessions/`와
  `tunnels/`가 독립된 디렉터리다.
- `core`/`runbooks`/`directory`/`evidence`/`reports`는 이름·범위 모두 일치.
- 문서에 전혀 언급 없는 폴더: `decoders`, `exploit_research`, `findings`, `graph`,
  `hash_cracking`, `operations`, `post_exploitation`, `privesc_analysis` — 그리고
  `modules/hosts.py`/`system.py`/`vpn.py`/`privesc_server.py`, 최상위 `executor.py`/
  `pty_manager.py`/`templates.py`/`nmap_parser.py`/probe·tree 스크립트들.

절반 가까운 모듈이 문서 작성 이후 추가된 것으로 보인다. `docs/ARCHITECTURE.md`의 표는
전면 갱신이 필요하지만, 이 저장소의 원칙 자체(자동 판정 금지 등)는 여전히 유효하다.

## 12. 크로스커팅 상태: Custom Event와 localStorage

프런트엔드는 별도 상태관리/pubsub 라이브러리 없이 `window` 레벨 `CustomEvent` 5종과
`localStorage`로 워크스페이스 간 상태를 공유한다(React Query 캐시 무효화와 별개).

### 12.1 Custom Event

| 이벤트 | detail | Dispatch 위치 | Listen 위치 |
|---|---|---|---|
| `oscp-project-change` | `number`(project id, 0=없음) | `AppShell.tsx`(선택/삭제), `App.tsx`(자체 선택기), `scanCenterModel.ts`의 `syncSelectedProject()`, `GraphWorkspace.tsx`(프로젝트 생성 후) | `AppShell.tsx`(헤더 갱신), `Root.tsx`(`projectRevision`++ → `AppShell` 전체 리마운트), `ScanCenter.tsx`, `RunbookWorkspace.tsx`, `GraphWorkspace.tsx` |
| `oscp-target-change` | `number`(target id) | `WebWorkspace`, `RunbookWorkspace`, `SessionWorkspace`, `App.tsx`, `PostExploitationWorkspace`, `HashCrackingWorkspace`, `ToolsWorkspace`, `ExploitResearchWorkspace`, `EvidenceWorkspace`, `ScanCenter` — 각자 로컬 대상 선택이 확정될 때마다 | `AppShell.tsx`(헤더의 "현재 Target" 표시) |
| `oscp-graph-refresh` | 없음(신호만) | `ScanCenter.tsx`(스캔 SSE 완료 직후, 새 서비스가 파싱된 뒤) | `GraphWorkspace.tsx`(`["graph", projectId]` 쿼리 무효화) |
| `oscp-service-nav` | 없음(payload는 `pendingServiceNav.ts` 모듈 상태) | `CommandPalette.tsx`, `GraphWorkspace.tsx`(service 노드 선택/딥링크) | `App.tsx`(`consumePendingServiceNav()`로 target/service 이동, 마운트 시에도 1회 소비) |
| `oscp-graph-focus` | 없음(payload는 `pendingGraphFocus.ts` 모듈 상태) | `pendingGraphFocus.ts`의 `focusInGraph()`(다른 워크스페이스의 "그래프에서 보기" 버튼이 호출) | `GraphWorkspace.tsx`(`consumePendingGraphFocus()`로 노드 선택+포커스) |

### 12.2 localStorage 키

| 키 | 저장값 | 용도 |
|---|---|---|
| `oscp-workspace-project` | project id(문자열) | 활성 프로젝트의 단일 source of truth. 거의 모든 워크스페이스가 마운트 시 읽고, 프로젝트 삭제 시 제거됨 |
| `oscp-sidebar-width` | 사이드바 px(184–420 clamp) | `AppShell.tsx` 사이드바 리사이즈 유지 |
| `oscp-sidebar-collapsed` | `"true"`/`"false"` | `AppShell.tsx` 사이드바 접힘 상태 |
| `oscp-graph-pane` | Progress Graph 우측 패널 px(최소 320) | `GraphWorkspace.tsx` 리사이즈 유지 |
| `oscp-web-launch` | JSON `{targetId, serviceId, url}` | Enumeration/Graph → Web Testing "이 URL 열기" 1회성 핸드오프, 소비 후 제거 |
| `oscp-crack-form-width` / `oscp-crack-history-width` | px | `HashCrackingWorkspace.tsx` 폼/이력 컬럼 리사이즈 |
| `oscp-workspace-hash-target` / `-mode` / `-value` | target id / hashcat 모드 / 해시 문자열 | `App.tsx`(Kerberoast/AS-REP/DCSync/NTLM 버튼) → `HashCrackingWorkspace.tsx` 1회성 핸드오프, 소비 후 제거 |
| `oscp-workspace-hash-label` | 자유 텍스트 라벨 | `App.tsx`가 기록하지만 읽는 곳이 없음(사실상 죽은 write) |
| `oscp-services-panel-width` / `-collapsed` | px / bool | `App.tsx` 서비스 목록 패널 리사이즈 |
| `oscp-execution-panel-width` / `-collapsed` | px / bool | `App.tsx` 실행 이력 패널 리사이즈 |
| `oscp-service-workspace-height` / `-collapsed` | px / bool | `App.tsx` 서비스 대시보드 패널 리사이즈 |
| `oscp-workspace-exploit-service` | service id | `App.tsx` → `ExploitResearchWorkspace.tsx` "이 서비스로 Exploit Research 열기" 핸드오프 |
| `oscp-command-palette-recent` | JSON 배열(최대 5개 id) | `CommandPalette.tsx` 최근 사용 항목 |
| `oscp-intruder-candidate-sets` | JSON 배열 | `IntruderPanel.tsx` 저장된 퍼징 후보값 세트 |

`sessionStorage["oscp-home-shown"]`(`Root.tsx`)은 별도로 브라우저 세션당 1회만 `#graph`로
강제 이동시키는 플래그다(§10 참고).

## 13. CSS 파일 구성

`frontend/src/`의 22개 CSS 중 대부분은 `main.tsx`가 전역으로 불러오고, 일부만 소유
컴포넌트가 직접 import한다.

| 파일 | Import 위치 | 담당 영역 |
|---|---|---|
| `styles.css` | `main.tsx` | 전역 베이스 테마(`:root` 커스텀 프로퍼티), 리셋/타이포그래피 |
| `layout-controls.css` | `AppShell.tsx` | `AppShell` chrome(사이드바 grid, 접기/리사이즈) |
| `command-palette.css` | `CommandPalette.tsx` | Ctrl-K 팔레트 모달 |
| `scan.css` | `main.tsx` | Scan Center 기본 레이아웃 |
| `scan-enhanced.css` | `main.tsx` | Scan Center 필터/작업 바 추가 스타일 |
| `enumeration-enhanced.css` | `main.tsx` | Service Enumeration(`App.tsx`) 추가 위젯 |
| `execution.css` | `main.tsx` | 실행/터미널 chrome(Enumeration과 공유) |
| `service-intelligence.css` | `App.tsx` | `ServiceIntelligencePanel` |
| `web.css` | `main.tsx` | Web Testing 기본 레이아웃 |
| `web-enhanced.css` | `main.tsx` | Web Testing 응답 이력/diff/클라우드 지문 |
| `evidence.css` | `main.tsx` | Evidence 워크스페이스 |
| `directory.css` | `main.tsx` | AD/Directory 워크스페이스 |
| `sessions.css` | `main.tsx` | Sessions 워크스페이스 |
| `reports.css` | `main.tsx` | Reports/Finding 기본 |
| `finding-advanced.css` | `FindingWorkspace.tsx` | Finding 목록/일괄 편집 |
| `finding-responsive.css` | `FindingWorkspace.tsx` | Finding 좁은 화면 대응 |
| `runbooks.css` | `main.tsx` | Runbook 워크스페이스 |
| `post-exploitation.css` | `main.tsx` | Post-Exploitation("loot") 워크스페이스 |
| `hash-cracking.css` | `HashCrackingWorkspace.tsx` | Hash Cracking 워크스페이스 |
| `exploit-research.css` | `main.tsx` | Exploit Research 워크스페이스 |
| `operations.css` | `main.tsx` | Operations 워크스페이스 |
| `template-manager.css` | `FindingTemplateManager.tsx` | Finding Template Manager 모달 |

## 14. 파일 크기 및 실행 제한

| 항목 | 코드에 정의된 제한 |
|---|---|
| Nmap XML | 10 MiB |
| Evidence upload | 50 MiB |
| HTTP response 보존 | 10 MiB |
| Intruder request 조합 | 최대 100 |
| OVPN config | 2 MiB |
| Exploit PoC import | 5 MiB |
| Exploit working-copy text | 1,000,000 bytes |
| LSASS dump upload | 300 MiB |
| ZIP upload for zip2john | 300 MiB |
| Scan live output | manager당 2,000,000 bytes |
| Post-Exploitation live output | manager당 2,000,000 bytes |
| Hash Cracking live output | manager당 2,000,000 bytes |

상수와 검증 위치는 각 router 및 manager에 있다
([`backend/app/nmap_parser.py`](../backend/app/nmap_parser.py),
[`backend/app/modules/evidence/router.py`](../backend/app/modules/evidence/router.py),
[`backend/app/modules/web_testing/router.py`](../backend/app/modules/web_testing/router.py),
[`backend/app/modules/vpn.py`](../backend/app/modules/vpn.py),
[`backend/app/modules/exploit_research/router.py`](../backend/app/modules/exploit_research/router.py),
[`backend/app/modules/decoders/router.py`](../backend/app/modules/decoders/router.py),
[`backend/app/modules/hash_cracking/router.py`](../backend/app/modules/hash_cracking/router.py)).

## 15. 실행과 검증 명령

```bash
./scripts/install.sh
./scripts/dev.sh
./scripts/build.sh
./scripts/start.sh
./scripts/test.sh
```

`scripts/test.sh`는 `.venv/bin/pytest backend/tests`와 frontend의 `npm run build`를
실행한다. frontend Vitest는 `cd frontend && npm test`로 별도 실행된다
([`scripts/test.sh`](../scripts/test.sh),
[`frontend/package.json`](../frontend/package.json)).

현재 테스트 파일은 `backend/tests/test_*.py`와 `frontend/src/*.test.ts(x)` 패턴으로
배치돼 있다.

## 16. 재시작 동작

- production backend code 변경은 실행 중인 uvicorn에 자동 반영되지 않는다.
- `dev.sh`는 uvicorn에 reload 옵션을 전달한다.
- backend launcher는 `*.yaml` 변경도 reload 대상으로 지정한다.
- frontend 개발 서버는 Vite를 사용한다.
- production frontend는 `frontend/dist`에서 제공되므로 build 결과가 사용된다.
- 환경 변수와 저장 경로는 module import 시 읽힌다.
- scan concurrency 변경 endpoint는 실행 중인 scan이 없을 때 manager의 semaphore를 즉시
  교체한다.
- backend 재시작 시 lifespan과 scan recovery가 미완료 작업 상태를 앞의 표와 같이
  변경한다.

관련 구현은 [`scripts/run-root-backend.sh`](../scripts/run-root-backend.sh),
[`backend/app/main.py`](../backend/app/main.py),
[`backend/app/modules/scan_center/router.py`](../backend/app/modules/scan_center/router.py)에 있다.
