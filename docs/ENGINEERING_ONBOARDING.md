# OSCP Workspace Source Reference

> 이 문서는 2026-08-08의 working tree를 대상으로 작성한 코드 탐색 자료다. 제품 평가,
> 정책 해석, 설계 권고, 우선순위와 개선 제안은 포함하지 않는다. 동작 설명은 링크된
> 소스코드와 실행 스크립트에서 직접 확인할 수 있는 내용으로 한정한다.

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

## 10. 파일 크기 및 실행 제한

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

## 11. 실행과 검증 명령

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

## 12. 재시작 동작

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
