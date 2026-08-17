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
     ├─ Note (project_id 필수, target_id/service_id/credential_id는 선택)
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
| Captured command | `modules/executions/router.py` | `executor.py`, output files, ftp-directory-tree 멤버 재다운로드(FTP 재접속) |
| Interactive session | `modules/sessions/router.py` | `pty_manager.py`, session logs, 종료 세션 `/retry` 재시작 |
| Web request | `modules/web_testing/router.py` | `HttpRequest`, `HttpExchange`, response files |
| Web proxy | `modules/web_proxy/router.py` | `manager.py`, mitmproxy addon |
| Evidence | `modules/evidence/router.py` | Evidence files, ZIP export, zip evidence 멤버 목록/추출(zip-slip 안전, 암호 걸린 멤버는 거부) |
| Note | `modules/notes/router.py` | `Note` rows (project 필수, target/service/credential 선택 스코프) |
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
process 처리는 [`backend/app/executor.py`](../backend/app/executor.py)에 있다. 실행 시작 로직
자체(target_dir/output_dir 계산, `catalog.render()`, `Execution` 행 생성, task 기동)는
`router.py`가 아니라 [`backend/app/modules/executions/service.py`](../backend/app/modules/executions/service.py)의
`start_execution()`에 분리돼 있다.

### AutoRecon (여러 대상 동시 정찰)

카탈로그 태그 기반으로 이 앱이 직접 팬아웃하는 방식을 먼저 만들어 라이브까지 검증했었지만,
실제 `autorecon`(Tib3rius) 바이너리를 pipx로 설치해 라이브 테스트해본 결과 막히는 기술적
블로커가 없다는 게 확인돼 **실제 도구를 서브프로세스로 감싸는 방식**으로 교체했다 — 서비스별
매칭 로직을 우리가 다시 짤 필요가 없고(AutoRecon 자체 플러그인이 담당), 여러 대상 동시
처리도 AutoRecon 자체 옵션(`-m`/`-mp`)이 처리한다. **중요**: PyPI의 `autorecon` 패키지는
완전히 무관한 다른 도구(Paul Schubert의 OSINT 툴)다 — 반드시
`pipx install git+https://github.com/Tib3rius/AutoRecon`로 GitHub에서 받아야 한다
(`backend/app/modules/system.py`의 TOOLS 안내 문구에도 명시).

```text
GET /api/autorecon/capabilities
  → 설치된 바이너리의 --version/--help/--list를 캐시해 모든 실행 옵션과
    PortScan/ServiceScan/Report 플러그인을 프런트 옵션 카탈로그에 제공
POST /api/autorecon/run {project_id, target_ids, arguments?}
  → AutoReconRun 행 생성(대상 여러 개를 하나의 실행으로 묶음 -- ScanJob과 달리
    항상 대상 1개=행 1개가 아니다)
  → render_autorecon_command()가 argv 구성:
    ["autorecon", *ip들, "--disable-keyboard-control", "--ignore-plugin-checks",
     *사용자 고급 인자, "-o", output_dir]
    (각 플래그가 왜 필수인지는 코드 주석 참고 -- 특히 --disable-keyboard-control
    없으면 TTY 없는 서브프로세스 환경에서 termios.error로 바로 죽는다, 라이브로 확인함)
  → AutoReconManager._run()이 서브프로세스 실행, stdout/stderr를 기존 실행/스캔과
    같은 SSE 이벤트 셰이프({"stream":"stdout"/"stderr"/"status", ...})로 스트리밍
    (stdin은 반드시 DEVNULL)
  → 프로세스 종료 시 import_autorecon_run(db, run) 호출
      실행 중 폴링은 최근 8초 내 수정된 파일을 건너뛰지만, 프로세스 종료 후 최종 패스는
      writer가 모두 닫혔으므로 quiet period 없이 즉시 임포트한다(짧은 실행 결과 유실 방지).
      never --single-target으로 실행하므로(대상 1개든 여러 개든) 결과는 항상
      <output_dir>/<대상 IP>/scans/... 형태 -- 라이브로 확인한 실제 레이아웃.
      대상마다 부기용 ScanJob(source="autorecon")을 하나 만들어 기존
      ingest_xml()/capture_scan_evidence()를 그대로 재사용(Service upsert,
      ServiceObservation, NSE 긍정 결과 자동 Finding까지 공짜로 얻음), 그다음
      scans/tcp<port>/와 scans/udp<port>/ 밑의 .txt/.html 파일마다(또는
      --no-port-dirs 사용 시 scans/ 바로 아래 파일마다, 파일명에서 플러그인 slug만 뽑아
      template_id="autorecon-<slug>") Execution을 직접 생성 -- 서브프로세스를 또
      띄우는 게 아니라 이미 끝난 결과 파일을 그대로 가져오는 것이므로
      start_execution()을 거치지 않는다. --force-services로 XML 포트 발견이 생략된 경우에는
      `tcp_80_http_<plugin>` 파일명의 서비스 slug를 보조 근거로 Service를 생성한다.
      AutoRecon의 exploit/loot/report 디렉터리도 원형대로
      생성하며, 완료 후 전역 스캔 출력·운영 로그·report/exploit/loot 실제 파일은
      ScanArtifact/Evidence로 등록한다.
  → 실행 중 activity는 별도 Run 노드가 아니라 대상 Host 메타에 기록돼 Host 중심 스캔
    이펙트를 구동한다. 종료 후에는 대상별 `AutoRecon 결과물 #<run_id>` technique을 Host 아래 만들고
    `/api/autorecon/results/{scan_job_id}`에서 scans/exploit/loot/report 트리를 탐색한다.
    파일 클릭은 `/preview` 인라인 뷰어, 다운로드는 `/download`, 캔버스 드래그는 `/promote`로
    Evidence + Draft Finding을 만들어 결과물 노드 아래에 영구 배치한다.
    서비스별 Execution은 Service 하위 technique으로 투영한다. 모든 원본 산출물은
    개별 중복 노드 대신 결과물 노드의 파일 트리와 Evidence에서 관리한다.
```

새 모듈은 `backend/app/modules/autorecon/`(scan_center의 router/service/manager 3분할을
그대로 따름) — 특히 `import_autorecon_run`
([`backend/app/modules/autorecon/service.py`](../backend/app/modules/autorecon/service.py))이
핵심이고, `AutoReconManager`
([`backend/app/modules/autorecon/manager.py`](../backend/app/modules/autorecon/manager.py))는
체이닝이 없어 `ScanManager`보다 훨씬 단순하다(세마포어 하나, 프로세스 하나, 끝나면 임포터
한 번 호출). `AutoReconRun`은 프로젝트 삭제 캐스케이드(`core/router.py`의 `delete_project`)와
active-run 가드에도 `scan_jobs`/`hash_crack_jobs`와 나란히 들어가 있다 — 새 project-scoped
테이블을 추가할 때 그 두 곳(가드 체크 + 삭제 목록)을 빼먹기 쉬우니 참고.

프런트는 새 워크스페이스가 아니라 기존 `ScanCenter.tsx`의 도구 선택 목록에 `autorecon`을
추가했다 — 선택하면 단일 스캔 설정 대신 이미 등록된 대상 체크박스 목록이 뜨고, "AutoRecon 시작"은 선택한
대상 전체를 담아 `POST /api/autorecon/run`을 **한 번만** 호출한다(대상마다 반복 호출하는 게
아님 -- 실제 도구가 이미 여러 대상을 한 프로세스로 처리하므로). 새 컴포넌트는
[`frontend/src/AutoReconPanel.tsx`](../frontend/src/AutoReconPanel.tsx) 하나뿐이고, 실제 설치본에서
발견한 전체 옵션/플러그인을 검색·선택할 수 있는 실행 구성 UI와 이 프로젝트의
실행 목록(`GET /api/autorecon?project_id=`)을 보여주다가 하나를 선택하면 자체
`EventSource('/api/autorecon/{id}/events')`로 라이브 트랜스크립트를 인라인 표시한다 —
`ScanCenter`의 단일 스캔 SSE `useEffect`와 이벤트 셰이프가 같아서 그 파싱 로직을 거의 그대로
가져다 썼다. 실행이 하나(프로세스 하나)뿐이라 여러 터미널을 동시에 띄우는 UI는 필요 없다.

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

**`window.prompt()`/`alert()` 금지 패턴**: 이 앱은 `window.prompt()`/`alert()`를
쓰지 않는다 — bare/root Kali Chrome(또는 dialog가 차단된 브라우저)에서는 native
dialog가 아예 뜨지 않고 `prompt()`가 조용히 `null`을 반환해, 버튼을 눌러도 아무
일도 없는 것처럼 보인다(`AppShell.tsx`의 프로젝트 추가 모달에 원래 있던 주석).
2026-08-16 세션에서 실제 사용자 흐름을 다시 걸어보다 이 정확한 증상으로 재현된 뒤
5곳을 in-app 모달로 교체했다: `App.tsx`의 `createTarget`("+ 대상") IP 입력과
`run()`의 `{username}` 대화형 인증 이름 입력, `OperationsWorkspace.tsx`의 동시
스캔 수 설정, `RunbookWorkspace.tsx`의 Template 복제 이름, `ScanCenter.tsx`의 스캔
alias·태그 편집. 새 입력 하나가 필요하면 `AppShell.tsx`의 `creatingProject`/
`newProjectName`/`createError` 3종 state + `className="modal"` `role="dialog"`
패턴을 그대로 따른다 — `confirm()`(삭제 확인 등)은 아직 별도 감사 대상으로 남아있다.

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
| `ReverseShellPanel.tsx` | 리버스쉘 페이로드 생성, webshell 다운로드, 안정화 치트시트. 리스너는 `nc -lvnp`(기본)와 `socat TCP-LISTEN:<port>,reuseaddr,fork -`(연결 하나 끊겨도 리스너 자체는 계속 듣고 있음, `fork` 덕분) 중 선택 — `onStartListener(command)`가 완성된 명령 문자열을 그대로 넘기므로 App.tsx는 `openManualShell(command)`만 호출한다(예전엔 포트만 받아 `nc` 명령을 여기서 직접 조립하는 `openListenerShell` 헬퍼가 있었지만, 리스너 종류 선택지가 생기면서 명령 조립 책임이 패널로 옮겨가 삭제됨) |
| `ChiselPivotPanel.tsx` | chisel server/client 명령 생성(SOCKS·단일 포트) |
| `ResponderPanel.tsx` | Kali 데스크톱 터미널에서 Responder 시작, 캡처 폴링 |
| `SmbShareResults.tsx` | SMB 공유 목록, 연결·재귀 목록, 첫 공유 자동 스파이더. "원문 보기"(`viewSmbFile`)는 원래 `smbget`을 썼는데 `smbget`엔 포트 옵션이 아예 없어 445 아닌 포트에선 항상 `Connection refused`로 실패했다(로컬 테스트 SMB 서버로 실제 재현) — 다른 SMB 템플릿과 동일하게 `smbclient -N //{host}/{share} -p {port} -c 'get {path} -'`로 교체(status 라인은 stderr로만 가서 stdout엔 파일 원문만 남음) |
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
| `PrivescSessionPanel.tsx` | LinPEAS/WinPEAS/pspy 파일 서버 토글, 세션 로그에서 NetNTLMv2 해시 폴링, 접힌 `LinuxPrivescReference.tsx`(수동 권한 상승 체크리스트 6개 카테고리 — 기본 정보/SUID·capability/cron·서비스 설정/배포판별 서비스 설정 파일 경로/쓰기 가능 파일·tty 안정화/제한된 셸·실행 환경 대응(rbash·BusyBox·noexec), `linuxPrivescCommands.ts`가 데이터 소스). 세션이 있을 때만 뜨는 이 위치와 달리 `PostExploitationWorkspace.tsx`(§10.11)엔 항상 렌더되는 같은 컴포넌트가 하나 더 있다 |
| `LiveOutputPanel.tsx` | 실시간 출력 패널(`D\|`/`F\|` 태그 출력은 파일 트리로 렌더) |
| `OperatorContext.tsx` | 그래프의 root/host ScanCenter와 service Enumeration이 공유하는 대상 프롬프트·실제 상태 fact·작업 액션 헤더 |
| `FloatingTerminal.tsx` | AppShell 전역 다중 터미널 창 관리자와 `DetachableTerminal` seam — Scan, Graph Execution, Service output, Tools, Hash Cracking, Post-Exploitation, PTY를 ID별 독립 창으로 분리하고 라우트와 무관하게 이동·3방향 크기 조절·원위치 도킹 |
| `XtermOutput.tsx` | 완료/스트리밍 명령 출력을 xterm.js 읽기 전용 버퍼로 렌더하는 전역 플로팅 로그 뷰 |
| `terminalFont.ts` | 모든 xterm PTY와 읽기 전용 출력의 공용 글자 크기(12-24px) 저장 및 실시간 동기화 |
| `FloatingCommandSession.tsx` | 플로팅 결과의 전체 실행 명령·target/service-bound 하단 prompt; 입력 시 bare Bash interactive session을 만들고 실제 PTY로 전환 |
| `PtyTerminal.tsx` | xterm.js + WebSocket으로 실제 서버 PTY를 렌더하고 입력·resize·종료를 중계하는 raw 터미널 뷰 |
| `SmartTerminalOutput.tsx` | raw stdout의 IP/URL/open service 후보를 파싱하고 승인형 Graph/browser/fuzz smart action을 제공 |
| `ServiceCommandSession.tsx` | Service에 바인딩된 명령 PROFILE 선택·컨텍스트 입력·editable argv·drift lock; captured는 Execution, interactive는 기존 PTY 경로로 staging. `{username}`만 필요하고 `{password}`는 없는 interactive 프로필(ssh-client 등)이 매칭되고 Credential Store에 알려진 계정이 있으면, PROFILE 선택 전에도 "알려진 계정으로 접속 시도" 콜아웃이 즉시 뜬다 — 클릭하면 그 프로필로 전환하고 username만 채운다(비밀번호는 그대로 인터랙티브 프롬프트로 남김); RUN은 여전히 사용자가 누른다. `serviceName`이 `sqlPayloads.ts`의 `dbPayloadCategoriesFor()`와 매칭되는 DB 엔진(postgresql/mysql/ms-sql-s)이면 접힌 "DB 페이로드 참고" 섹션도 뜬다 — `SqlPayloadReference`를 그대로 재사용하되 인젝션 컨텍스트 페이로드는 제외하고 각 엔진의 기초 문법·정찰 카테고리 + "이미 인증된 클라이언트에 직접 입력" RCE 변형만 보여줌(웹 SQLi 없이 크리덴셜로 DB에 직접 붙은 상황용) |

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
| `AutoReconPanel.tsx` | Scan Center 도구 목록에서 `autorecon`을 선택했을 때 렌더 — 대상 다중 선택 체크박스, SCOPE 확인, `POST /api/autorecon/run`(대상 배열 한 번에) 호출, 이 프로젝트의 실행 목록(`GET /api/autorecon?project_id=`)과 선택한 실행의 라이브 SSE 트랜스크립트(`/api/autorecon/{id}/events`) |
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
| `SqlPayloadReference.tsx` | SQLi 페이로드 치트시트(복사/Intruder 전송, 자동 실행 없음), tun0 IP + LPORT 자동 채움({LHOST}/{LPORT}는 리버스 쉘 페이로드가 있는 항목에만 있음: PostgreSQL COPY FROM PROGRAM, MSSQL xp_cmdshell, MySQL SELECT INTO OUTFILE 웹셸/UDF sys_exec, Redis SSH 키·크론 심기/모듈 로드 — `sqlPayloads.ts`). postgres/mysql/mssql 각각 RCE 카테고리 앞에 "기초 문법·정찰" 카테고리(버전·현재 사용자·계정 해시·파일 읽기/쓰기 등)가 있고, redis/mongodb는 RCE와 정찰을 한 카테고리(`redis-basics`/`mongodb-basics`)에 합쳐놨다 — mongodb-basics만 NoSQL 인젝션(`$ne`/`$regex`) 인젝션 컨텍스트 페이로드도 포함. 각 페이로드는 `context: "direct"`(이미 인증된 클라이언트/UNION 등에 바로 입력) 또는 `"injection"`(웹 파라미터로 인젝션)으로 태그돼 있다(redis-basics는 전부 direct, 주입 경로가 없음). `categories` prop으로 카테고리 서브셋을 넘길 수 있어 `ServiceCommandSession.tsx`가 DB 서비스일 때 `dbPayloadCategoriesFor()`로 필터링한(인젝션 변형 제외) 서브셋을 재사용해 임베드한다. 각 카테고리 `<details>`엔 `id={sqlpayload-<category.id>}`가 있어 Command Palette가 "postgres"/"mysql"/"mssql"/"redis"/"mongodb" 검색으로 해당 카테고리까지 직접 딥링크(펼침+스크롤)한다 — `commandPaletteIndex.ts`의 `web/sqli-postgres`/`web/sqli-mysql`/`web/sqli-mssql`/`web/sqli-redis`/`web/sqli-mongodb` 항목 |
| `LfiPayloadReference.tsx` | LFI/경로 순회 페이로드 치트시트, tun0 IP 자동 채움 |
| `Log4ShellPayloadReference.tsx` | CVE-2021-44228 JNDI probe 카탈로그 |
| `ProxyPanel.tsx` | mitmproxy 패시브 캡처(시작/중지, CA 인증서 다운로드), 클라우드 지문 배지 |
| `murmurHash.ts` / `curlImport.ts` | Shodan favicon 해시 계산 / cURL → 요청 초안 파서(비-컴포넌트 헬퍼) |

### 10.4 `EvidenceWorkspace.tsx` — 증적 (`#evidence`)

대상별 파일/스크린샷/플래그/마크다운 업로드(드래그앤드롭), 메타데이터 편집(제목,
사용자명/호스트명/획득 권한, 민감도, 보고서 포함 여부, 태그), Exploit Research 후보
연결, 선택적 ZIP export. 목록은 종류·원본 파일·출처·획득 시각·크기를 표시하고,
command output/Nmap XML/HTTP/Markdown 등 텍스트 파일은 최대 256 KiB까지 오른쪽에서
미리본을 제공한다. 하위 컴포넌트 없음.
API: `/targets`, `/evidence?target_id=`, `/evidence/{id}`, `/evidence/{id}/preview`, `/evidence/upload`,
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
| `InteractiveTerminal.tsx` | `PtyTerminal`을 `DetachableTerminal`에 연결하는 wrapper; `autoFloat` 세션은 AppShell 전역 xterm으로 즉시 분리되어 노드·워크스페이스 전환에도 유지됨; `PrivescSessionPanel.tsx`(App.tsx의 손자)도 사용. `floatTerminal()`은 뜨는 순간의 `props`를 딱 한 번만 캡처하므로, `DetachableTerminal`이 이미 갖고 있던 "떠 있는 동안도 `updateTerminal()`로 content 갱신" 이펙트를 `autoFloat` 경로에도 똑같이 붙여놨다(deps: `inputRequest`/`initialInput`/`title`/`isFloating`) — 없으면 이미 뜬 터미널에 나중에 새 `inputRequest`를 보내도(그래프 Inspector의 manual-shell 트리거 등) 얼어붙은 옛 props만 보고 있어서 조용히 무시된다 |

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
nxc로 approve→execute 실행, 출력 스트리밍(트리 명령은 파일 트리 렌더). LinPEAS 붙여넣기
분석은 `LinpeasAnalysisPanel.tsx`(critical/high/medium 분류, Finding 승격, `targetId`/
`projectId`/`onAnalyzed` props로 독립된 컴포넌트) — `features/graph/Inspector.tsx`의
`manual-shell` 세션 블록(§10.14)도 같은 컴포넌트를 재사용해 그래프에서 바로 결과를
붙여넣을 수 있다. SUID/GTFOBins 분석도 같은 패턴으로 `SuidAnalysisPanel.tsx`(GTFOBins
매칭, Finding 승격, 동일한 `targetId`/`projectId`/`onAnalyzed` props)로 분리돼 있고,
Inspector의 `manual-shell` 세션 블록도 이 컴포넌트를 재사용한다. SUID/GTFOBins 분석 아래에 접힌
`LinuxPrivescReference.tsx`(`onSendCommand` 없이, 복사 전용)도 항상 렌더된다 —
`PrivescSessionPanel.tsx`의 것과 달리 활성 세션·target 선택과 무관하게 항상 존재하는
페이지라서, `linuxPrivescCommands.ts`의 6개 카테고리 전부가 Command Palette에서
`post-exploitation/<category id>` 항목(예: "pg_hba.conf" 검색 → `config-paths`,
"rbash"/"busybox"/"noexec" 검색 → `restricted-shell`)으로 개별 딥링크되는 유일한
진입점이다. "linpeas" 검색은 별도 `post-exploitation/linpeas` 항목(`anchorId:
"linpeas-heading"`)으로 `LinpeasAnalysisPanel.tsx`의 결과 분석 섹션까지 딥링크한다.
API: `/projects`, `/targets`, `/runbooks/credentials?project_id=`,
`/post-exploitation/catalog`, `/post-exploitation*`, `/targets/{id}/linpeas`,
`/targets/{id}/suid-scan`, `/findings`.

| 하위 컴포넌트 | 역할 |
|---|---|
| `fileTree.tsx` | `D\|`/`F\|` 태그 라인 → 접기 가능 파일 트리 파서/렌더러; `LiveOutputPanel.tsx`/`NetexecOutcome.tsx`(App.tsx의 손자)도 사용 |
| `FloatingFilePreview.tsx` / `floating-file-preview.css` | AutoRecon 결과 파일용 이동·8방향 크기 조절 작업창; 텍스트/XML 터미널 렌더링과 `Ctrl+F` 내부 검색, 이미지/PDF 미리보기 |

### 10.12 `HashCrackingWorkspace.tsx` — Hash Cracking (`#hash-cracking`)

해시 붙여넣기(정규식 카탈로그로 모드 자동 감지) 또는 zip 업로드(`zip2john`), 공격
모드(straight/combination/mask/hybrid) 선택, 실행+실시간 출력, 크랙된 평문을
Credential Store로 승격. `oscp-workspace-hash-*` localStorage 키로 App.tsx의
Kerberoast/AS-REP/DCSync/NTLM 해시 "크래킹으로 보내기" 버튼과 연결. 하위 컴포넌트
없음(리사이즈 패널 로직은 인라인).
API: `/projects`, `/targets`, `/hash-cracking/catalog`, `/hash-cracking*`,
`/hash-cracking/{id}/promote`, `/hash-cracking/zip2john`.

### 10.13 `ToolsWorkspace.tsx` — Tools (`#tools`)

자동 서비스 분류에 의존하지 않는 전체 명령 카탈로그(130개) 탐색 — Nmap이 놓쳤거나
오분류한 서비스(예: WinRM을 http로 인식)를 위한 대안 경로. 대상 선택 → 서비스 또는
수동 포트/스킴 입력 → 변수 채움 → 검토 → 실행(스트리밍 또는 데스크톱 대화형 세션).
API: `/projects`, `/targets`, `/targets/{id}/services`, `/tool-catalog`,
`/executions*`, `/interactive-sessions*`.
하위 컴포넌트: `CommandReviewModal.tsx`(App.tsx와 공유).

### 10.14 `features/graph/GraphWorkspace.tsx` — Progress Graph (`#graph`, 기본 홈)

프로젝트 전체를 보여주는 허브: project-root → host → service/finding/technique/credential
노드의 force-directed Canvas 2D 그래프(nmap target/service에서 자동 동기화 + 수동 추가
노드/엣지), 같은 Canvas를 계층 배치하는 트리 모드, 기존 DOM Outline 뷰, 노드 상태 편집,
숨김 토글, 우측 상세 패널은 일반
Inspector(하위 노드 추가 폼) 또는 — project-root/host 노드
선택 시 `ScanCenter.tsx`를, service 노드 선택 시 `App.tsx`를 `embedded` prop으로 그대로
끼워넣는다(`lazy(() => import(...))`, 자체 chrome는 숨김). Execution에서 투영된 모든
technique 노드는 원본 실행 상태·대상/서비스·명령·stdout/stderr/error를 표시한다.
명령 시작으로 execution 노드가 추가될 때는 기존 Canvas 좌표를 700ms 유지하고 새 노드를
부모 근처에서 먼저 안정화해, topology 갱신이 화면 전체를 밀어내는 들썩임을 방지한다.
`http-link-extract`는 여기에 유형순 링크 목록, Evidence 파생 저장과 Web Testing Request
handoff를 추가로 제공하며, handoff 시 그래프를 벗어나지 않고 우측 GraphRequestPanel에서
편집·저장·전송·응답 검토까지 수행한다. GraphRequestPanel은 `/vpn/status`의 tun0 IPv4를
UNC 경로로 URL 커서 또는 `page=` 값에 삽입하는 SMB Direct Injection 단축과 존재하지 않는
호스트명의 UNC 경로를 삽입하는 LLMNR 시도 단축도 제공한다.
GraphRequestPanel엔 쿠키 편집 필드(`COOKIES · JSON`)와 `body_mode`(raw/json/form/
multipart) 선택이 있다 — 백엔드(`web_testing/router.py`)는 둘 다 처음부터 지원했지만
(httpx `cookies=`, `files=`), 그래프에서 핸드오프되는 이 패널만 `cookies: {}`로
고정하고 body_mode도 raw뿐이라 실제로 쓸 방법이 없었다(쿠키 편집은 그래프 밖의 전체
Web Testing 페이지 `WebWorkspace.tsx`에만 있었음 — 접근통제 우회용 쿠키 변조 같은
작업마다 그래프를 벗어나야 했다). `multipart`를 고르면 `BODY` 텍스트영역 대신 필드명 +
`<input type=file>` + 추가 필드(JSON)로 바뀌고, 프런트가 파일을 `FileReader`로
base64 인코딩해 `body`에 `{fields, files: [{field, filename, content_type,
content_b64}]}` 형태로 담아 보낸다 — 백엔드는 `body_mode == "multipart"`일 때 이걸
파싱해 httpx `files=`로 실제 업로드 요청을 만든다(스냅샷엔 base64 원문 대신 바이트
수만 남겨 커진 요청을 그대로 저장하지 않는다).
`App.tsx`의 웹 서비스 패널에서 가장 눈에 띄는 CTA인 "Web Testing에서 열기" 버튼은
`openLinkInRequest`를 거치지 않고 `location.hash="web"`로 무조건 그래프를 벗어났다
— `http-link-extract` 결과 목록의 개별 링크 액션에만 그래프 내 GraphRequestPanel
경로(`onOpenRequestInGraph`)가 연결돼 있었다. 쿠키/멀티파트 지원을 그래프 패널에
추가해도 실제 사용자가 맨 처음 누르는 버튼이 그래프를 떠나면 소용없다는 걸 라이브
재검증으로 확인하고, 이 버튼도 `openLinkInRequest(webUrl)`을 호출하도록 통일했다
(embedded일 땐 버튼 라벨도 "Request 패널 열기"로 바뀐다).
`GraphRequestPanel`엔 "요청 편집기"/"Log4Shell · JNDI 리스너" 탭도 있다 — Log4Shell
카탈로그(`Log4ShellPayloadReference.tsx`)와 신규 `JndiRceListenerPanel.tsx`는
원래 `WebWorkspace.tsx`(`#web` 독립 라우트)에만 있었고 `WebWorkspace`는 `embedded` prop
자체가 없어 그래프 안에서 도달할 방법이 아예 없었다(HTB Unified의 Log4Shell foothold를
매핑하다 발견). WebWorkspace 전체를 embeddable하게 만드는 대신, 이미 그래프 네이티브인
GraphRequestPanel에 그 두 컴포넌트를 그대로 재사용하는 두 번째 탭을 붙였다.
`JndiRceListenerPanel.tsx`는 `backend/app/modules/jndi_listener.py`의
`/api/jndi-listener/{start,stop,status}`를 호출한다 — 이 백엔드 모듈은 marshalsec이나
별도 다운로드 없이 순수 Python 소켓으로 최소 LDAP 서버(bind는 전부 성공, search는 전부
`javaNamingReference` referral 하나로 응답)를 구현하고, `javac`(런타임에 확인,
없으면 `sudo apt install default-jdk` 안내)로 LHOST/LPORT를 박은 `Exploit.java`를
컴파일해 별도 `http.server` 서브프로세스로 서빙한다. 구조는 `privesc_server.py`와
동일한 `_process`/`_port` 전역 + `_state()` 패턴을 따르되, LDAP 절반은 서브프로세스가
아니라 스레드다(외부 바이너리가 없어 소켓을 직접 붙잡고 있어야 함). 실제 취약한 대상이
없어 RCE 성공까지는 검증할 수 없지만, `ldapsearch`(독립 실 LDAP 클라이언트)로 실제
bind+search 왕복과 referral 속성을, `javap`로 컴파일된 클래스에 LHOST/LPORT가 정확히
박혔는지를 로컬에서 확인했다.
같은 이유(HTB 박스 풀이 흐름이 그래프 UI 어디에도 이어질 곳이 없었음)로 이후
`GraphRequestPanel`엔 두 탭이 더 붙었다 — "Langflow RCE"(`LangflowRcePayloadReference.tsx`,
CVE-2026-33017 `build_public_tmp` 페이로드, `langflowRcePayload.ts`가 데이터 소스)와
"JWT alg:none 위조"(`JwtForgePanel.tsx`, `jwtForge.ts` — 순수 클라이언트 base64 인코딩이라
백엔드 호출 없음, 위조한 토큰을 바로 Authorization 헤더에 꽂는 핸드오프 포함). `Inspector.tsx`의
manual-shell 세션 노드엔 `LinuxPrivescReference`/`WindowsPrivescReference`와 완전히 같은
복사-전용(+세션이 열려 있으면 `onSendCommand`로 PTY 직접 전송) 모양의 참고 체크리스트가 세
개 더 접혀 들어간다 — `McpExploitReference.tsx`(`mcpExploitCommands.ts`, MCP 서버는 박스마다
스키마가 달라 표준 REST가 없으므로 확정 명령이 아니라 시작 템플릿), `K8sPivotReference.tsx`
(`k8sPivotCommands.ts`, 파드 RBAC 자기권한 확인 → hostPath 특권 파드 탐색 → kubelet
exec 웹소켓 API로 그 파드 진입까지 4개 카테고리), `GiteaTemplateSyncReference.tsx`
(`giteaTemplateSyncCommands.ts`, Gitea API 토큰 발급 → template 레포 생성 →
`git update-index --cacheinfo`로 일반 `git add`로는 못 만드는 `../` 트리 항목을 인덱스에
직접 삽입해 root-owned 동기화 타이머의 path traversal을 트리거 → push까지). 이 넷은
전부 HTB 박스(Fireflow/Nexus) 풀이 과정을 매핑하다가 이 앱에 전례 없던 도메인으로 확인돼
그래프에 갓 붙은 것들이라, `docs/ARCHITECTURE.md`의 모듈 표에는 아직 없다.
정상적으로 서빙 중인 Gitea 같은 저장소(노출된 `.git`이 아니라)에서 커밋 히스토리까지
포함해 클론하는 `git-history-clone`/`git-history-log` catalog 명령도 `services.yaml`의
`web` 섹션에 새로 붙었다 — `git-dumper-clone`/`git-dump-tree`와 나란히 있지만
git-dumper는 노출된 `.git/` 디렉터리를 대상으로 하고, 이 둘은 `{domain}`(Host 헤더로 vhost
지정, `http-vhost-fuzz`와 같은 토큰)과 `{path}`(owner/repo.git)를 받아 정식 clone을 수행한다
— 지워진 커밋의 자격증명을 찾을 때 쓴다.
Finding과 credential 작업도 라우트를 바꾸지 않는다. Finding은 `ReportWorkspace.tsx`,
credential은 `HashCrackingWorkspace.tsx`와 `PostExploitationWorkspace.tsx`를 각각
`embedded` 인터페이스로 우측 패널에 lazy-load한다. 이 어댑터는 프로젝트·대상·해시·모드·
credential ID와 사용자명을 초기값으로 넘긴다. Credential에서 시작한 크랙 결과는 사용자명을
다시 묻지 않고 기존 Credential에 평문과 HashCrackJob 출처를 연결한다. 원본 폼, 실행 터미널,
결과, Evidence 저장, 이력 기능은 그대로 재사용한다. 패널 폭이 좁으면 container query로
이력을 아래로 재배치하며 숨기지 않는다.
`mongodb-info` 무인증 확인이 성공한 노드는 `UnauthAccessResult`로 mongosh 접속 버튼과
`mongodb-db-tree`(DB·컬렉션 이름 나열, `backend/app/mongodb_tree.py`) 결과를 보여주는데,
원래는 그 트리를 `<pre>`로 그냥 텍스트 덤프만 했다 — 실제 문서 내용(예: HTB Unified의
`ace.admin` 컬렉션에 있는 UniFi 로그인 bcrypt 해시)을 보려면 mongosh를 직접 열어 타이핑해야
했다. `UnauthAccessResult`에 `onOpenTreeFile` prop을 추가해 트리를 `FileTreeView`(다른
파일 트리들과 같은 컴포넌트)로 바꾸고, 리프를 클릭하면 새 템플릿
`mongodb-collection-dump`(`backend/app/mongodb_collection_dump.py`, pymongo로
`db[collection].find().limit(20)`을 JSON으로 출력)를 `/executions`로 새로 실행해 결과를
같은 패널 아래에 보여준다 — `SmbShareResults`/`viewSmbFile`과 동일하게 "클릭마다 새
captured 실행을 만들고 폴링" 구조이며, `FileContentModal`(매뉴얼 셸의 살아있는 PTY 세션
기반 파일 읽기)과는 다른 메커니즘이다(`mongodb-info` 무인증 확인엔 PTY 세션이 없음).
`onOpenTreeFile`이 없으면 기존처럼 `<pre>` 그대로 렌더되므로 SNMP OID 트리 등 다른
`UnauthAccessResult` 사용처는 영향 없음.
Credential 노드 Inspector는 저장된 인증정보의 크래킹 여부와 출처를 먼저 표시하고, 평문 또는
해시를 명시적으로 확인·복사할 수 있게 한다. Canvas 라벨도 `CAPTURED`, `CRACKED`, `READY`로
상태를 구분한다. 평문(해시 아님)이고 사용자명이 있으면 "SSH로 시도" 버튼도 뜬다 —
NetExec 자격증명 확인 노드의 `openSsh`는 체크 명령 argv에서 `-u`/`-p`를 정규식으로
읽지만, hash-crack-job 등에서 나온 순수 credential 노드는 그런 명령 문자열이 없어
같은 방식을 쓸 수 없다. 이 credential 전용 SSH 액션을 위해 `targets` 쿼리의
`enabled` 조건도 execution/session 노드뿐 아니라 credential 노드에서도 켜지도록
넓혔다(HTB Unified의 마지막 단계 — MongoDB에서 크랙한 비밀번호를 root SSH에
재사용 — 를 그래프에서 클릭만으로 잇기 위해 추가).
`manual-shell` 세션 노드는 들어오는 `attempted` 관계로 대상·서비스를 복원하고, 일반
Inspector로 열린다 — Inspector가 `PrivescSessionPanel.tsx`(App.tsx 쪽 세션 뷰)와 같은
구성을 그대로 그래프에 옮겨왔다: 노드 상태가 `attempt-failed`(백엔드 `failed`/
`interrupted` 매핑, `graph/service.py`)면 "세션 열기" 대신 "다시 시작 (\<명령\>)" 버튼이
뜬다 — Responder 리스너 전용인 줄 알았던 `retry()`/`POST /interactive-sessions/{id}/retry`가
실제로는 이미 완전히 범용이라(같은 command/target/service/graph_parent로 새 세션 row만
만듦) manual-shell에 그대로 재사용했다. 죽은 프로세스에 "세션 열기"로 재접속을 시도하면
당연히 실패하는데도 이 노드 유형만 재시작 버튼이 없었던 게 갭. 살아있는 세션엔 그대로
"세션 열기" 토글, tun0
임시 파일서버(같은 `/privesc-server/*`)를 켜고 열린 세션의 PTY에 LinPEAS/WinPEAS/pspy
다운로드 명령을 직접 입력하는 트리거(manual-shell은 nc 리스너·SSH뿐 아니라 evil-winrm도
거치는 합성 template_id라 Windows 셸도 흔함 — WinPEAS도 같이 넣음), 붙여넣기 기반
`LinpeasAnalysisPanel.tsx`/`SuidAnalysisPanel.tsx`(§10.11 참고), 그리고 접힌
`LinuxPrivescReference.tsx`/`WindowsPrivescReference.tsx`(`windowsPrivescCommands.ts`가
데이터 소스 — `linuxPrivescCommands.ts`와 완전히 같은 구조: `win-basic-info`/
`win-powershell-history`/`win-services-tasks` 3개 카테고리, `id={winprivesc-<category
id>}`로 Command Palette 딥링크, `PostExploitationWorkspace.tsx`에도 나란히 항상
렌더됨. PowerShell 히스토리 조회 명령 자체는 `credential_hunt.yaml`의
`windows_browser_script_env`로 이미 있었지만 SSH/wmiexec 카탈로그 실행 전용이라
그래프의 manual-shell/evil-winrm 세션에서 열린 셸로는 보낼 방법이 없었다 — "이미
있다"와 "그래프 UI 조작으로 이어진다"는 다른 질문이라는 걸 보여주는 사례,
세션이 열려 있을 때만 `onSendCommand`를 넘겨 PTY로 직접 타이핑, 아니면 복사 전용으로
폴백)까지 그 자리에서 제공한다. 예전엔 이 노드 유형을
선택하면 항상 대상의 Post-Exploitation 패널을 `file_tree` 실행 우선 상태로 곧장
임베드해 Inspector 자체가 렌더되지 않았는데(Post-Exploitation 이동 없이 라이브 셸을
바로 만질 방법이 없었음), 지금은 그 SSH 카탈로그 기반 폴더·파일 트리 뷰가 "다른
자격증명으로 조회 (SSH)" 버튼(`GraphWorkspace.tsx`의 `fileTreePanel` 상태, `onBack`으로
복귀)으로 대체돼 필요할 때만 연다.
같은 자리의 "폴더·파일 트리 조회 (현재 셸)" 버튼은 그 SSH 경로와 별개로, 저장된
자격증명이 아예 없는 순수 리버스쉘(`nc -lvnp` 등)에서도 동작하는 진짜 대안이다 —
이미 열려 있는 PTY에 마커로 감싼 `find` 한 줄(`echo ___TREE_START_<marker>___; find
${FILE_TREE_SCOPE} -mindepth 1 \( -type d -printf 'D|%p\n' \) -o -printf
'F|%p\n' | head -5000; echo ___TREE_END_<marker>___`, `linux_file_tree` 카탈로그
명령과 같은 스코프)을 입력한 뒤, 세션 자신의 영속 로그(`/interactive-sessions/{id}/log`)를
1.5초 간격으로 폴링해 그 마커 쌍 사이만 잘라 `parseTaggedTreeLines`로 파싱하고
`FileTreeView`로 그린다(45초 안에 마커를 못 찾으면 포기하고 에러 메시지 표시).
`FILE_TREE_SCOPE`(Inspector.tsx 모듈 상수, `credential_hunt.yaml`의
`linux_file_tree`와 동일)는 `/home /root /tmp /var/www /opt /srv /var/backups /etc`
— 처음엔 앞의 넷뿐이었는데, `pg_hba.conf`처럼 `/etc` 아래 있는 설정 파일까지 놓치지
않으려고 사용자 요청으로 `/etc`까지 넓혔다(노이즈 감수 — `/etc`가 압도적으로 커서
`head` 컷오프를 다 먹어버릴 수 있어 스코프 목록 맨 뒤에 두고, 작고 신호가 높은 폴더가
먼저 채워지게 순서를 잡았다). PTY는
실행 전에 입력한 명령 자체를 그대로 되돌려 찍기 때문에 로그에 각 마커가 두 번(에코된
명령 줄 + 실제 출력) 나타난다 — `indexOf`가 아니라 `lastIndexOf`로 뒤쪽(진짜 출력) 것을
집어야 한다는 게 라이브 검증 없이 놓치기 쉬운 부분이라 회귀 테스트가 그 순서를 그대로
재현한다. 같은 턴에 `linux_file_tree`(SSH 카탈로그 버전) 자체도 실제로 실행해보지
않으면 안 보이는 버그가 있었다는 게 드러났다 — `find -printf '%y|%p'`의 `%y`는
소문자(`f`/`d`)를 찍는데 파서(`parseTaggedTreeLines`)와 파일 내용 읽기
(`_read_tree_file`)는 둘 다 대문자 `F|`/`D|`만 인식해서, 실제 SSH로 돌리면 트리가
항상 빈 채로 나왔다 — `credential_hunt.yaml`도 같이 고쳐 `-type d`/그 외로 명시적으로
분기해 대문자 태그를 직접 찍게 했다.
이 블록의 모든 트리거가 공유하는 `sendToManualShell(command, autoRun?)`은 항상 `\x15`
(Ctrl-U, readline의 kill-to-start-of-line)를 명령 앞에 붙여 PTY로 보낸다 — 클릭할
때마다 대기 중이던 줄을 지우고 새 명령으로 교체하기 위함이다(없으면 LinPEAS를 두 번
누르거나 LinPEAS 다음 WinPEAS를 누르는 식으로 서로 다른 트리거를 연달아 누를 때마다
전 명령 뒤에 계속 이어붙어서 실행 안 되는 한 줄짜리 쓰레기 텍스트만 쌓였다 — 실제
라이브 세션에서 이렇게 재현됐다). `autoRun`은 기본 false(다른 트리거들과 같은 "검토 후
Enter" 원칙 — LinPEAS/WinPEAS/pspy/`LinuxPrivescReference`는 제3자 스크립트를
받아 실행하거나 카탈로그 전체를 검토 없이 자동 실행하기엔 범위가 넓어서 사람이 확인하고
직접 Enter를 눌러야 한다); 폴더·파일 트리 트리거만 `autoRun: true`로 호출한다 —
이 명령은 앱이 고정으로 만든, 사용자가 편집할 수 없는 순수 읽기 전용 `find`라 검토
단계가 안전상 의미가 없고, 그냥 `ls`/`dir`를 직접 치는 것과 리스크가 다르지 않기
때문이다(명령 끝에 `\r`을 붙여 전송). 이 두 가지(클리어 후 교체, 트리거별 자동 실행
여부) 모두 실제 라이브 세션에서 사용자가 겪은 문제를 보고 고친 것이라 §11.1의
"실제로 실행해서 검증" 원칙 사례로 `OBVIOUSNESS_STANDARD.md`에도 기록돼 있다.
`manual-shell`은 리버스쉘 리스너·SSH 퀵커넥트·redis-cli 등 `/interactive-sessions/manual`로
여는 모든 세션이 공유하는 합성 `template_id`라 카탈로그에 실제 항목이 없다 — 그래프 라벨은
`graph/service.py`의 `_session_label()`이 이 경우만 `sess.command`(예: `nc -lvnp 4444`, 60자
초과 시 말줄임)로 대체하고, 다른 template_id는 그대로 `_catalog_label()`을 쓴다. 이미
"manual-shell" 그 자체로 저장된 기존 노드도 다음 sync에서 라벨이 그 문자열 그대로일 때만
자동으로 재라벨링된다(사용자가 직접 고친 라벨은 건드리지 않음 — 서비스 노드의 "still-default
label" 재정제와 같은 원칙).
Windows 폴더·파일 트리 명령은 `C:\\` 루트를 명시적으로 포함해 드라이브 전체를 조회한다.
완료된 트리는 실시간 shell 상태가 아니라 해당 실행 시각의 저장된 조회 결과로 표시한다.
Time Machine 재생 중에도 Canvas/Outline 노드 선택은 허용하며, 우측 읽기 전용 패널에서 당시
노드의 유형·상태·요약·메모·기록 시각을 확인한다. 실행과 편집만 LIVE 복귀 전까지 막는다.
NetExec execution 노드 Inspector는 저장된 실행 출력에서 인증 결과를 복원하고 대상의 최신
Post-Exploitation `file_tree` 결과도 함께 표시한다. Enumeration 패널은 서비스 재진입 시 최신
NetExec 실행과 저장된 파일 트리를 API에서 다시 hydrate하므로 컴포넌트 state 소멸에 의존하지 않는다.
Responder session 노드는 대상의 캡처 로그를
4초마다 프로젝트 단위로 조회해 새 캡처를 중복 없이 Credential로 저장하고 그래프에
반영하며, 해시 보기·복사를 제공한다. `credential` 노드는 기본적으로
Post-Exploitation handoff를 제공하고, `credType=hash`이면 실제 secret/target을 채우는 Hash
Cracking handoff도 함께 제공한다. 실행 중인 스캔은 host 노드, 실행 중인 명령·세션은
technique 노드의 `meta.activity`에 투영되어 Canvas에서 녹색 레이더 파동·스윕·엣지
패킷으로 표시되며 종료 시 제거된다. 데스크톱 Responder는 PID가 살아 있는 동안 별도의
빨간 `LISTENING` 레이더로 표시되고 2초 동기화로 창 종료를 반영한다. Responder는 대상
Host의 자식이 아니라 `Kali Operator · <tun0 IP>` 아래 `runs`로 배치되고, 대상에는 방향성
비구조 엣지 `captures-from`(`AUTH CAPTURE`)으로 연결된다. 프로젝트가 없으면 "start"
합성 노드로 프로젝트 생성을 유도한다. 그래프 모드는 anchor 주위에
DISCOVERY→ENUMERATION→ACCESS→PRIVILEGE→EVIDENCE의
옅은 단계 링을 그린다. service/execution/finding/credential 메타는 sync 때 최신 값으로
갱신되어 노드 hover/선택 요약(제품·버전, 실행 시간·exit/error, 심각도·Evidence 수,
credential 유형)에 쓰인다. 우하단 Activity Stream은 `created_at`과 실행 시작 시각을 합쳐
최대 100건을 최신순으로 보여주며 클릭하면 해당 노드를 선택하고 중앙으로 이동한다. 검색,
유형·상태 필터, 최신/오래된 정렬을 제공한다. 헤더 드래그로 이동하고 헤더·우하단의 명시적인 handle로
크기를 조절하며 최소화 버튼으로 접을 수 있다. 위치·크기·접힘은 저장하고 viewport가 바뀌면
handle이 화면 밖으로 잘리지 않도록 좌표를 clamp한다. 미완료 상태는
DB enum을 바꾸지 않고 UI에서 준비됨/선행 정보 부족/사용자 검토 대기/실행 중/재시도 가능/
적용 불가로 번역한다. 선택한 그래프·트리·Outline 모드는 `oscp-graph-view`에 유지한다.
그래프 작업 바는 label/메타/메모/태그 검색, 유형·상태 필터, 선택 노드 기준 1~3-hop 집중,
북마크 전용 보기와 필터 초기화를 제공한다. 노드 우클릭 메뉴는 상세 열기, 연결 작업 추가,
전역 컨텍스트 바와 Time Machine·그래프 필터 바는 캔버스 세로 공간을 확보하는 compact
desktop chrome을 사용하며 VPN 상세 주소와 DNS 입력은 전역 헤더에서 축약한다.
북마크, 상태 변경, 숨기기와 노드 제거를 제공한다. 노드 제거는 project-root를 제외한
GraphNode와 연결된 GraphEdge를 삭제한다. 원본 데이터에서 자동 투영된 노드는
`GraphProjectMeta.layout.dismissedSourceRefs`에 삭제 표식을 남겨 이후 sync에서도 다시
생성되지 않는다. Inspector의 메모와 북마크는 GraphNode의 기존
`notes`/`pinned` 필드를 PATCH하므로 서버에 영속된다. Work Queue는 수동 technique과
실행·실패 상태 작업을 모아 노드 이동 및 상태 전환을 제공한다. Canvas pan/zoom/노드 배치는
프로젝트·보기 모드별 localStorage에 저장되며 선택 노드도 복원된다.
GraphCanvas/OutlineView/Inspector/AddNodeForm/ProjectOperatorSession 등은
`features/graph/` 하위 파일로 분리돼 있다. `ProjectOperatorSession.tsx`는 project-root를
실행기가 아닌 Target·최근 세션 TUI 라우터로 렌더하며, host는 source_ref의 target id를
`ScanCenter`에 직접 전달한다.
완료·exit 0인 SSH/WMIExec/WinRM/secretsdump RemoteExecution은 사용 Credential에서 목적
host로 `reused-credential`, Credential을 획득한 source host에서 목적 host로
`pivoted-to` edge를 idempotent하게 투영한다. 후자는 실제 network pivot이 아니라
Lateral Access provenance이며 edge meta가 원본 RemoteExecution을 보존한다. Canvas의
`🔑 ACCESS LINEAGE` overlay는 Credential을 계정·유형 badge로, 두 관계를 방향성 amber/cyan
화살표로 표시하며 저장된 secret은 그리지 않는다. 실패·timeout·미실행은 lineage가 되지 않는다.
Scan과 Service raw terminal은 `SmartTerminalOutput.tsx`를 공유한다. IP, URL,
`port/protocol open service`를 겹치지 않게 파싱해 underline Candidate로 표시하며 사용자가
메뉴에서 승인한 경우에만 child Graph node 생성, 브라우저 열기 또는 Enumeration의
ferox/ffuf 폼으로 handoff한다. Candidate는 자동으로 Graph를 수정하지 않는다.
Graph Time-Machine은 `GraphEvent` append-only snapshot을 사용한다. 동일 fingerprint의
연속 상태는 저장하지 않고 과거 frame은 읽기 전용으로 렌더한다. 배포 이전 데이터는
node/edge `created_at` 순서로 fallback 재생한다.
`docs/UI_UX_REVIEW.md`의 추천 1~4에 따라 (2026-08-13) 다음이 추가됐다 — (1) host/
service/credential 노드에도 finding처럼 `meta.evidenceCount`를 동기화(`graph/service.py`,
credential은 `Credential.source_execution_kind`/`source_execution_id` 체인을 통해서만
집계됨)하고 캔버스에 작은 초록 원형 배지로 표시("사람이 첨부한 Evidence가 있다"는
뜻일 뿐 자동 검증 아님), (2) 🎯 PATH TO OBJECTIVE 토글 — 선택 노드에서 `objective`
플래그가 켜진 가장 가까운 노드까지 BFS(엣지를 양방향으로 취급, `focusDepth`와 같은
연결성 규칙)로 경로를 찾아 금색 halo로 강조, (3) 프로젝트 생성 이후 경과 시간을
`⏱ H:MM:SS`로 툴바에 상시 표시(OSCP+ 23:45:00 제한 참고용, project-root 노드의
`created_at` 기반 순수 클라이언트 계산), (4) `discovered`/`enumerated`/`attempted` 등
구조적 엣지에도 방향 화살표 추가(이전엔 `captures-from`/Access Lineage 엣지에만 있었음).
관련 순수 함수(`evidenceCount`, `pathToObjective`, `formatElapsed`)는 `graphModel.ts`에 있다.
`파일 발견`/`파일 다운로드` finding 라벨에서 확장자를 뽑아 zip/json/pem/jpg 등에 각각 다른
pictogram(`fileFindingGlyph`)을 Canvas에 그린다(flag 판정과 같은 파일명 추출 로직 공유).
finding Inspector는 연결된 Evidence마다 다운로드 링크를 보여주며, zip evidence는 "압축 해제"로
멤버 목록을 펼쳐 각각을 새 Evidence+Draft Finding으로 그래프에 다시 올릴 수 있다(`/evidence/
{id}/archive`, `/evidence/{id}/extract` — 항상 `archive.read()`만 쓰고 엔트리 이름을 파일
경로로 쓰지 않아 zip-slip에 안전하며, 암호로 보호된 멤버는 목록에서부터 🔒로 표시하고
추출을 막는다). 암호 보호된 zip은 "Hash Cracking으로 보내기"로 `/evidence/{id}/zip2john`을
호출해(hash_cracking 모듈의 `run_zip2john`을 재사용, 재업로드 없이 evidence의 디스크 파일을
직접 읽음) 추출한 해시·모드를 embedded Hash Cracking 패널에 바로 채워 넣는다
(`CredentialHandoff.hash_mode_id`). archive 멤버(암호 없는 것만), FTP 다운로드 목록 항목,
`ftp-directory-tree` 트리(실행 노드 자신의 것과 세션 Inspector에 인라인으로 뜨는 것 둘 다)의
파일도 post-exploitation 파일 트리와 같은 `FILE_DRAG_MIME` 페이로드(`fileTree.tsx`의
`FileDragPayload` — `kind`로 구분되는 discriminated union)로 Canvas에 드래그해 그래프
노드로 추가할 수 있다(`FileTreeView`는 `runId`뿐 아니라 임의의 `dragPayload` factory를
받으므로, 새 tree 종류를 드래그 가능하게 만들 때 이 prop만 넘기면 된다). `-oX`로 결과를 저장하는 catalog 명령(`service-version`/
`service-version-udp`/`telnet-info`/`telnet-version-trace`/`database-info`는 Service 행에,
`target-hostname-redirect`/`target-hostname-identity`/`target-os-identity`는 Target 행에) 은
완료 시 `executor.py`가 이미 관찰값을 자동 반영하므로, Inspector도 raw stdout 대신 반영된
값을 바로 요약해 보여준다(`target-hostname-ntlm`은 이 목록에서 제외 — 참고용일 뿐 자동
저장되지 않는다고 catalog 설명에 명시돼 있다). 반대로 ftp/imap/nfs/rsync/redis-key-tree/
mssql/postgres/docker/git-dumper의 "성공하면 후속 tree 명령을 자동 실행" 페어는 아직 이
요약 패널이 없다 — mongo/snmp/mysql/webdav/ldap/svn(모두 Phase 2에서 포팅됨)와 정확히 같은
`App.tsx`의 `autoRun*Tree` 패턴이지만, 이 트리들은 credStore 폼 입력으로 트리거되거나(ftp/
imap/postgres) 별도 confirm 커맨드가 없어 아직 Inspector 쪽 `isXCheck` 짝이 없다. 다만
raw stdout이 거짓을 말하는 건 아니다 — 트리 자체의 그래프 노드를 직접 선택하면 결과를 볼 수
있으니, 위 auto-save 케이스처럼 "약속과 다르게 동작"하는 버그는 아니고 미완성 UX 롤아웃이다.
scan_center의 `capture_scan_evidence()`가 nmap NSE 긍정 결과(예: ftp-anon)로 자동 생성하는
"Needs Review" finding 후보 중, 제목이 `Ftp Anon on {ip}:{port}` 형태인 것은 Inspector가
정규식으로 host/port를 그대로 읽어 "익명으로 접속하기" 버튼 하나로 anonymous/anonymous@를
미리 입력한 대화형 FTP 세션을 띄운다(`docs/FINDING_REPORTING.md` §Automatic scan evidence
참고 — 이 자동 Finding 자체는 Phase 1부터 있던 기존 동작). 이때 `InteractiveSessionIn.
graph_node_id`로 그 finding 노드를 함께 넘겨서, 세션 동기화(`sync_from_project`)가 그
세션을 host/service가 아니라 그 finding의 자식(`attempted` 관계)으로 붙인다
(`InteractiveSession.graph_parent_node_id` 컬럼). `ftp-directory-tree`/`git-dump-tree`/
`http-webdav-tree`/`nfs-export-tree`/`rsync-module-tree` 다섯 개는 전부 post-exploitation
파일 트리와 같은 `D|`/`F|` 태그 형식을 쓰므로(각 스크립트 자체 주석에 "other tree
commands와 같은 형식"이라고 명시) raw stdout 대신 `FileTreeView`로 렌더한다.
`ftp-directory-tree`는 추가로 파일 클릭/드래그 시 `/executions/{id}/promote-ftp-file`로
같은 호스트/포트/자격증명으로 재접속해 그 파일 하나만 다시 받아 Evidence+Draft Finding으로
승격한다(`ftp_tree.py` 자체는 목록만 만들고 내려받지 않으므로 조회와 다운로드가 분리돼
있음). 나머지 네 개는 아직 이 재다운로드 짝이 없다 — 트리 렌더링만 개선됐다. `ftp-client`
템플릿의 대화형 세션은 (데스크톱/웹 터미널, 익명 접속 버튼 구분 없이) 생성되는 순간
`create_interactive_session`이 익명 `ftp-directory-tree` 크롤을 자동으로 큐에 넣는다(같은
target+service에 이미 실행이 있으면 건너뜀) — 세션 자신의 Inspector가 그 결과를 target+
service로 찾아와 "폴더·파일 트리" 섹션에 바로 렌더하므로, 그 세션에서 발견된 파일을 보려고
별도의 "폴더·파일 트리 조회" 실행 노드를 따로 찾아갈 필요가 없다.
`HashCrackJob`도 Execution/InteractiveSession과 같은 패턴으로 `technique` 노드로 동기화된다
(`sync_from_project`) — service 차원이 없어(크래킹은 로컬 실행) host에 바로 `attempted`로
붙는 게 기본값이지만, `HashCrackJob.graph_parent_node_id`가 설정돼 있으면(zip2john처럼
특정 finding에서 해시를 뽑아 보낸 경우) 그 finding 밑에 붙는다 — `InteractiveSession`과
동일한 override 패턴(`JobIn.graph_node_id` → `CredentialHandoff.graph_node_id` →
`HashCrackingWorkspace`의 `initialGraphNodeId` prop으로 이어짐). credential 노드는
SPEC_GRAPH_TRACKER §1.4상 항상 구조적 리프라 `attempted`의 source가 될 수 없으므로,
override 대상이 credential 타입이면 host로 폴백한다. `Credential.source_execution_kind==
"hash_crack_job"`인 credential이 있으면 그 job 노드에서 그 credential 노드로 `yielded`
엣지를 긋는다(Responder 리스너 → credential과 동일 패턴). 완료돼도 `cracked_count>0`이면
자동으로 성공 판정하지 않는다(다른 technique와 같은 원칙) — 단 워드리스트를 다 써도
하나도 못 깨면(`completed`+`cracked_count==0`) `attempt-failed`로 자동 강등한다.
`hash_crack_job` 노드를 Inspector에서 선택하면 Execution 노드와 같은 실시간 출력 패널이
뜬다(`GET /hash-cracking/{id}`+`/output`을 실행 중일 때 2초 간격으로 폴링) — 크랙된
항목이 있으면 사용자명을 입력해 `/hash-cracking/{id}/promote`로 Credential로 승격하는
카드도 같이 뜨고, 승격되면 다음 sync에서 자동으로 `yielded` 엣지가 생긴다. 프런트엔드
`GraphCanvas.tsx`의 activity 신호는 `scan`/`execution`/`listener` 3종에 `crack`이 추가돼
4종이며, `crack`은 다른 kind가 공유하는 breathing-ring 펄스나 회전 sweep을 그리지 않고
대신 노드 주위로 이진수(0/1)가 위에서 아래로 흘러내리는 전용 "디코딩" 이펙트를 그린다
(보라색 `#b388ff`로 다른 세 신호와 구분). `interactive_sessions`/`hash_crack_jobs`의
`graph_parent_node_id` 컬럼은 둘 다 Alembic 마이그레이션(`0037_graph_parent_node_id`)으로
추가됐다 — `database.py`의 `ensure_compatible_schema()`는 Alembic 이전부터 있던 소수의
원시 테이블(`scan_jobs`/`services`/`executions`)에만 쓰는 레거시 경로이므로, 새 컬럼은
이 경로가 아니라 `alembic/versions/`에 새 리비전 파일을 추가하는 것이 맞다.
API: `/projects`(POST), `/projects/{id}/graph`, `/projects/{id}/graph/sync`(POST, idempotent),
`/projects/{id}/graph/tree`, `/projects/{id}/graph/timeline`,
`/projects/{id}/graph/nodes`(POST), `/projects/{id}/graph/edges`(POST),
`/graph/nodes/{id}`(PATCH), `/executions/{id}/output`, `/executions/{id}/derive`,
`/executions/{id}/promote-ftp-file`(POST), `/interactive-sessions`(POST),
`/interactive-sessions/manual`(POST),
`/targets`, `/targets/{id}/services`, `/projects/{id}/responder-captures/sync`(POST),
`/evidence/{id}/archive`, `/evidence/{id}/extract`(POST), `/evidence/{id}/zip2john`(POST).

### 10.15 인프라/공용 파일 (특정 워크스페이스에 속하지 않음)

`Root.tsx`(해시 라우터), `AppShell.tsx`(영속 헤더/nav/프로젝트 선택 shell —
`VpnControl.tsx`, `CommandPalette.tsx`, `MetasploitLock.tsx` 포함), `CommandPalette.tsx`
(Ctrl-K 전역 팔레트, `commandPaletteIndex.ts`로 인덱싱), `MetasploitLock.tsx`(단일 대상
Metasploit 잠금 배너), `ui.tsx`(Badge/Button/Card/EmptyState/ErrorState/LoadingState/
PageHeader/statusCopy), `api.ts`(fetch 래퍼), `main.tsx`(Vite entry), `anchorUtils.ts`
(`revealAnchor()` — Ctrl-K/딥링크 앵커가 접힌 `<details>` 안에 있을 때 조상 `<details>`를
강제로 열어서 스크롤 대상이 실제로 보이게 함; `App.tsx`의 `scrollToAnchorSoon`과
`CommandPalette.tsx`의 `activate()` 양쪽에서 앵커로 스크롤하기 직전에 호출).

`ServiceIntelligencePanel.tsx`는 이전 서비스 조사 카드 UI의 회귀 테스트를 위해 남겨 둔
legacy 컴포넌트이며 현재 production workspace에서는 렌더링하지 않는다. 기본 서비스
작업 경로는 `ServiceCommandSession.tsx`이고, 세부 프로토콜 도구는 접힌 toolbox 안에서만
필요할 때 연다. 그 밖의 top-level 컴포넌트는 14개 워크스페이스 중 하나에 연결돼 있다.

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
| `graph` | Progress Graph 트리/DAG, Credential/Access Lineage와 append-only Attack Replay snapshot, spec: `docs/SPEC_GRAPH_TRACKER.md` | `/api`(tags=Graph) | `service.py` |
| `hash_cracking` | hashcat job lifecycle, 모드 자동 감지, 크랙 결과 → Credential 승격 | `/api/hash-cracking` | `router.py`(276) |
| `notes` | project/target/service/credential에 선택적으로 붙는 독립 Note CRUD(id/author/timestamp 보유) | `/api/notes` | `router.py`(72) |
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
| `modules/jndi_listener.py` | Log4Shell(CVE-2021-44228) 실전 RCE용 rogue LDAP(순수 소켓, 스레드) + 컴파일된 `Exploit.class` HTTP 서버(subprocess) | `/api/jndi-listener` |

`scan_center/service.py`의 `_safe()`와 `import_xml`/`ingest_xml`은 core, evidence,
exploit_research, findings, hash_cracking, post_exploitation, privesc_analysis, tunnels,
web_testing 등 다른 모듈에서도 널리 import된다 — 사실상 자기 도메인을 넘어선 공용
유틸리티 허브다.

### 11.1 `docs/ARCHITECTURE.md` 모듈 표와의 차이 (해결됨, 2026-08-10)

과거 `docs/ARCHITECTURE.md`는 `core`/`scans`/`enumeration`/`runbooks`/`web`/`directory`/
`sessions`/`evidence`/`reports` 9개 개념적 모듈 표를 별도로 유지했는데, 실제
`backend/app/modules/` 폴더 이름·개수와 벌어져 있었다(작성 시점 이후 스캐폴딩이 늘어난
것으로 보인다). `docs/ARCHITECTURE.md`는 이제 표를 두지 않고 이 문서의 §6/§11을
참조하도록 갱신했다 — 같은 목록을 두 문서에서 관리하면 다시 벌어지므로, 파일 단위
사실은 이 문서에서만 유지한다. 아래는 당시 벌어져 있던 내용의 기록이다.

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
| `oscp-graph-refresh` | 없음(신호만) | `ScanCenter.tsx`(스캔 SSE 완료 직후), `PostExploitationWorkspace.tsx`(원격 실행 종료 직후) | `GraphWorkspace.tsx`(`["graph", projectId]` 쿼리 무효화) |
| `oscp-service-nav` | 없음(payload는 `pendingServiceNav.ts` 모듈 상태) | `CommandPalette.tsx`, `GraphWorkspace.tsx`(service 노드 선택/딥링크) | `App.tsx`(`consumePendingServiceNav()`로 target/service 이동, 마운트 시에도 1회 소비) |
| `oscp-graph-focus` | 없음(payload는 `pendingGraphFocus.ts` 모듈 상태) | `pendingGraphFocus.ts`의 `focusInGraph()`(다른 워크스페이스의 "그래프에서 보기" 버튼이 호출) | `GraphWorkspace.tsx`(`consumePendingGraphFocus()`로 노드 선택+포커스) |

### 12.2 localStorage 키

| 키 | 저장값 | 용도 |
|---|---|---|
| `oscp-workspace-project` | project id(문자열) | 활성 프로젝트의 단일 source of truth. 거의 모든 워크스페이스가 마운트 시 읽고, 프로젝트 삭제 시 제거됨 |
| `oscp-sidebar-width` | 사이드바 px(184–420 clamp) | `AppShell.tsx` 사이드바 리사이즈 유지 |
| `oscp-sidebar-collapsed` | `"true"`/`"false"` | `AppShell.tsx` 사이드바 접힘 상태 |
| `oscp-floating-scan-terminal` / `oscp-floating-terminal-frame` | JSON Scan 세션 메타 / `{x,y,width,height}` | Scan 세션 reload 복원과 모든 전역 플로팅 터미널의 마지막 배치·크기 복원(일반 출력 내용은 민감정보·용량 때문에 localStorage에 저장하지 않음) |
| `oscp-scan-dock` | JSON `{scanId,targetId,projectId}` | 플로팅 터미널 원위치 복귀 시 같은 프로젝트의 Scan Center에만 적용되는 1회성 선택 핸드오프 |
| `oscp-graph-pane` | Progress Graph 우측 패널 px(최소 320) | `GraphWorkspace.tsx` 리사이즈 유지 |
| `oscp-graph-view` / `oscp-graph-activity-panel` | 보기 모드 / JSON `{x,y,width,height,collapsed}` | Graph/Tree/Outline 선택과 Activity Stream 배치·크기·접힘 유지 |
| `oscp-graph-selected` / `oscp-graph-camera:<root>:<mode>` | node id / JSON `{panX,panY,zoom,positions}` | 선택 노드와 프로젝트·레이아웃별 Canvas 작업 위치 복원 |
| `oscp-graph-replay:<projectId>` | epoch milliseconds | Time-Machine에서 선택한 읽기 전용 frame 복원; LIVE 복귀 시 삭제 |
| `oscp-web-launch` | JSON `{targetId, serviceId, url}` | Enumeration/Graph → Web Testing "이 URL 열기" 1회성 핸드오프, 소비 후 제거 |
| `oscp-smart-fuzz-url` | URL 문자열 | terminal Smart Action → Service Enumeration ferox/ffuf target 1회성 handoff |
| `oscp-crack-form-width` / `oscp-crack-history-width` | px | `HashCrackingWorkspace.tsx` 폼/이력 컬럼 리사이즈 |
| `oscp-workspace-hash-target` / `-mode` / `-value` | target id / hashcat 모드 / 해시 문자열 | `App.tsx`(Kerberoast/AS-REP/DCSync/NTLM 버튼) → `HashCrackingWorkspace.tsx` 1회성 핸드오프, 소비 후 제거 |
| `oscp-workspace-hash-label` | 자유 텍스트 라벨 | `App.tsx`가 기록하지만 읽는 곳이 없음(사실상 죽은 write) |
| `oscp-services-panel-width` / `-collapsed` | px / bool | `App.tsx` 서비스 목록 패널 리사이즈 |
| `oscp-execution-panel-width` / `-collapsed` | px / bool | `App.tsx` 실행 이력 패널 리사이즈 |
| `oscp-service-workspace-height` / `-collapsed` | px / bool | `App.tsx` 서비스 대시보드 패널 리사이즈 |
| `oscp-command-palette-recent` | JSON 배열(최대 5개 id) | `CommandPalette.tsx` 최근 사용 항목 |
| `oscp-intruder-candidate-sets` | JSON 배열 | `IntruderPanel.tsx` 저장된 퍼징 후보값 세트 |

`sessionStorage["oscp-home-shown"]`(`Root.tsx`)은 별도로 브라우저 세션당 1회만 `#graph`로
강제 이동시키는 플래그다(§10 참고).

## 13. CSS 파일 구성

`frontend/src/`의 CSS 중 대부분은 `main.tsx`가 전역으로 불러오고, 일부만 소유
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
| `execution-review.css` | `main.tsx` | Scan/서비스/도구 명령 실행 전 staging review 모달 |
| `floating-terminal.css` | `FloatingTerminal.tsx` | AppShell 전역 플로팅 터미널 이동·우측/하단/모서리 크기 조절 chrome |
| `smart-terminal.css` | `SmartTerminalOutput.tsx` | stdout token underline, Smart Action command menu, staged fuzz target |
| `features/graph/graph-time-machine.css` | `GraphTimeMachine.tsx` | Graph replay playhead, LIVE/READ-ONLY 상태 |
| `features/graph/project-operator-session.css` | `ProjectOperatorSession.tsx` | project-root의 Target router·최근 세션 TUI |
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
