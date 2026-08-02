# Claude Code / Codex Handoff

이 파일은 두 도구가 저장소를 다시 조사하는 비용을 줄이기 위한 짧은 인수인계 문서다.
의미 있는 구현을 마칠 때마다 작업한 도구가 **현재 상태**, **검증**, **다음 작업**을
갱신한다. 상세한 과거 기록은 `docs/WORKLOG.md`, 설계 원칙은
`docs/ARCHITECTURE.md`, 제품 용어는 `CONTEXT.md`를 참고한다.

## 현재 상태

- 브랜치: `phase-8/stabilization`
- 최근 기능 커밋:
  - `b5e17f5` — Masscan discovery와 Nmap 후속 스캔
  - `2427d7c` — Post-exploitation credential hunting
  - `0167ea8` — core/Execution/Session backend 라우트 모듈화
  - `10495b6`..`fe3f8be` — Enumeration scope/dashboard/credential UI 단계별 모듈화
- 진행 중: 백엔드와 프런트엔드의 점진적 모듈화
- 원칙: URL, 요청/응답 형식, DB 스키마를 유지하며 작은 단계로 파일만 분리한다.

## 현재 작업

- `backend/app/main.py`에서 product/project/target/service 메타데이터 라우트를
  `backend/app/modules/core/router.py`로 이동했다.
- `need()`와 `safe_part()`는 `backend/app/modules/core/support.py`에서 공유한다.
- Execution CRUD/output/SSE/stop 라우트를
  `backend/app/modules/executions/router.py`로 이동했다.
- Interactive Session HTTP/WebSocket/desktop/PTY 라우트를
  `backend/app/modules/sessions/router.py`로 이동했다. PTY manager shutdown은 앱
  lifespan 책임이므로 `main.py`에 유지한다.
- `main.py`에는 앱 조립, lifespan, audit middleware, system status와 정적 프런트
  제공만 남아 있다.
- `test_directory.py`, `test_evidence.py`의 가짜 업로드를 실제 multipart와 같은
  `SpooledTemporaryFile` fixture로 바꿔 Python 3.13/AnyIO timeout을 제거했다.
- 프런트엔드 `App.tsx` 1차 분리 진행 중:
  - 도메인 타입, 표시 상수와 PTY `shellQuote`를 `enumerationModel.ts`로 이동
  - shell quoting 회귀 테스트 추가
  - 공통 fetch 처리를 `api.ts`로 이동
  - 프로젝트→Target→Service→명령/intelligence/실행 조회를
    `useEnumerationQueries.ts`로 이동하고 활성화 조건·URL 테스트 추가
  - 서비스 개수·목록·빈 상태·선택 UI를 `ServiceList.tsx`로 이동하고 독립 테스트 추가
  - 실행 이력 목록·상세·출력·중단 UI와 결과 요약을 `ExecutionHistory.tsx`로 이동하고
    독립 테스트 추가
  - 동시 실행 monitor의 focus·중단·경과 시간·상태 신호 경고를
    `ExecutionMonitor.tsx`로 이동하고 독립 테스트 추가
  - 서비스 제품·버전·태그·메모 draft, 체크리스트, 저장 상태 UI를
    `ServiceWorkspace.tsx`로 이동하고 독립 테스트 추가
  - 최종 명령·sudo 선택·고위험 경고·실행/취소 UI를 `CommandReviewModal.tsx`로
    이동하고 독립 테스트 추가
  - 프로젝트·Target 선택, Nmap XML 업로드와 도구 상태 UI를
    `EnumerationScope.tsx`로 이동하고 선택·업로드 회귀 테스트 추가
  - 프로토콜별 인증 명령, 실행 상태·경과 시간과 노출 결과 UI를
    `CredentialAuditPanel.tsx`로 이동하고 검토·실행 상태 테스트 추가
  - 서비스 미확인 정보 계산, Target 자동 확인, NSE 관찰과 빠른 명령 UI를
    `ServiceDashboard.tsx`로 이동하고 요약·실행 중 상태 테스트 추가
  - 완료된 조사를 제외하는 규칙, 명령 카드와 실행 중 상태 UI를
    `InvestigationCommandList.tsx`로 이동하고 남은/완료 명령 테스트 추가
  - 프로토콜 인증 문맥·수동 접속 안내를 `ManualGuidance.tsx`, 현재 작업 상태·신호
    지연 경고를 `JobStatus.tsx`로 이동하고 독립 테스트 추가
  - 저장 자격증명 선택·삭제, NetExec 단일 계정 입력, 출처·비밀 저장 UI를
    `CredentialStoreForm.tsx`로 이동하고 인증 실행 잠금 테스트 추가
  - NetExec 성공 판정, 후속 psexec/SSH/WinRM/RDP/MSSQL/hashcat 및 Evidence/Finding
    액션을 `NetexecOutcome.tsx`로 이동하고 SMB 관리자 결과 테스트 추가
  - 권한 상승 스크립트 서버(LinPEAS/WinPEAS)와 psexec InteractiveTerminal 영역을
    `PrivescSessionPanel.tsx`로, 실시간 출력(상태 헤더·에러 메시지·실행 결과 요약·
    출력 텍스트)을 `LiveOutputPanel.tsx`로 이동하고 각각 독립 테스트 추가.
  - 현재 `App.tsx`는 최초 2,062줄에서 1,110줄로 축소됐다.
- `ScanCenter.tsx`(최초 1,131줄) 분리 완료:
  - 타입·상수·유틸(Scan/Profile/Obs/Artifact/Automation, `terminal`, `profileLabel`,
    `privilegedKinds`, `toolProfileGroups`, `get`, `serverTime`, `elapsed`, `bytes`,
    `syncSelectedProject`)을 `scanCenterModel.ts`로 이동. 기존
    `ScanCenter.test.ts`는 `scanCenterModel.test.ts`로 이름을 바꾸고 새 경로에서
    import한다. `PostExploitationWorkspace.tsx`의 `syncSelectedProject` import
    경로도 갱신했다.
  - 스캔 도구(Nmap/masscan) 선택 UI를 `ScanToolPicker.tsx`로 이동.
  - 대상 등록, 프로필 선택·구성, Nmap XML 가져오기, 명령 미리보기와 검토 버튼을
    `ScanProfileComposer.tsx`로 이동.
  - 현재 스캔 상태, 자동 증적/체이닝/masscan 발견 포트 안내를 `ScanJobStatus.tsx`로
    이동.
  - 스캔 검색·필터, 대기열/이력 목록, 취소·재실행과 비교(diff) UI를
    `ScanHistoryPanel.tsx`로 이동.
  - 각 컴포넌트에 독립 테스트 추가. `ScanCenter.tsx`는 1,131줄 → 603줄로 축소됐다.
    관찰 결과 테이블/필터/통계, artifact 패널, 저장·실시간 출력 터미널은 이번
    단계에서 그대로 두었다(다음 분리 후보).
- 백엔드 `runbooks/router.py`(최초 1,185줄) 분리 완료:
  - Pydantic 모델(TemplateIn/StepIn/PublishIn/ApplyIn/StepUpdate/ApprovalIn/
    LinkIn/CredentialIn/ObservationIn/FindingIn/FindingUpdate/CloneIn/DismissIn/
    ImportIn), 상수(STATUSES/OUTCOMES/REASON_REQUIRED/NODE_TYPES/
    ACTIVATION_LOCKED)와 공용 헬퍼(need/loads/seconds_since/
    instance_scope_current/template_dict/version_dict/progress/instance_dict/
    condition_met/credential_ids/observations/event/link_scope/
    service_fingerprint)를 `backend/app/modules/runbooks/support.py`로 이동.
  - 템플릿 CRUD/publish/versions/clone/archive/export/import, instance
    list/create/get/recompute, recommendations(service·target)/dismiss,
    activity, findings CRUD/export, summary를
    `backend/app/modules/runbooks/workflow_router.py`로 이동.
  - step 상태 갱신, 승인 결정, 타이머, evidence/execution/credential 첨부,
    observation 생성·promote를
    `backend/app/modules/runbooks/execution_router.py`로 이동.
  - credential CRUD와 credential 추천을
    `backend/app/modules/runbooks/credentials_router.py`로 이동.
  - 기존 `router.py`는 삭제했다. 세 라우터 모두 동일한
    `prefix="/api/runbooks"`를 쓰므로 URL은 그대로다. `main.py`가 세 라우터를
    모두 `include_router`한다.
  - 외부에서 `runbooks.router`를 이름으로 import하던 지점(`service_intelligence
    /router.py`, `test_runbooks.py`, `test_targets.py`,
    `test_builtin_runbooks.py`)을 새 파일 경로로 갱신했다.

## 검증

- Python bytecode compile: 통과
- Session 집중 backend 테스트: 7 passed
- Session 연동 frontend 테스트: 12 passed
- 전체 backend suite: `125 passed in 32.10s`
- Frontend production build: 통과
- Chrome production smoke: Scan Center, Service Enumeration, Sessions,
  Post-Exploitation 정상 렌더링. Chrome console error 없음. 관찰된 asset/API 요청은
  모두 HTTP 200. `/tmp/oscp-browser-validation`의 격리 DB와 프로필을 사용했다.
- Frontend model 분리 후: 전체 Vitest `19 files / 60 tests` 통과, production build
  통과, Chrome Service Enumeration 재검증 및 모든 관찰 요청 HTTP 200.
- Frontend query 분리 후: 전체 Vitest `20 files / 61 tests` 통과, production build
  통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend service-list 분리 후: 전체 Vitest `21 files / 63 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend execution-history 분리 후: 전체 Vitest `22 files / 65 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend execution-monitor 분리 후: 전체 Vitest `23 files / 67 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend service-workspace 분리 후: 전체 Vitest `24 files / 69 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend command-review 분리 후: 전체 Vitest `25 files / 70 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend scope-controls 분리 후: 전체 Vitest `26 files / 72 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 렌더링, console error 없음,
  모든 관찰 asset/API 요청 HTTP 200.
- Frontend credential-audit 분리 후: 전체 Vitest `27 files / 74 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend service-dashboard 분리 후: 전체 Vitest `28 files / 76 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend investigation-list 분리 후: 전체 Vitest `29 files / 78 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend guidance/job-status 분리 후: 전체 Vitest `31 files / 80 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend credential-store-form 분리 후: 전체 Vitest `32 files / 81 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상 및 모든 관찰 요청 HTTP 200.
- Frontend netexec-outcome 분리 후: 전체 Vitest `33 files / 82 tests` 통과,
  production build 통과, Chrome Service Enumeration 정상, console error 없음,
  모든 관찰 asset/API 요청 HTTP 200.
- Frontend privesc-session/live-output 분리 후: 전체 Vitest `35 files / 87 tests`
  통과, production build 통과. Chrome 검증: 격리 DB(`/tmp/oscp-browser-validation`)에
  프로젝트·대상·SSH/SMB 서비스(nmap XML 직접 업로드)를 만들어 Service Enumeration에서
  두 서비스 모두 렌더링 확인, SMB NetExec 자격증명 확인 섹션과 그 아래 실시간 출력
  패널까지 정상 표시, console error 없음. (참고: 브라우저의 `window.prompt()` 기반
  "+ 대상" 흐름은 CDP 자동화와 상성이 나빠 API로 직접 시드했다 — 기존 UI 동작 자체의
  회귀는 아니다.)
- ScanCenter 분리 후: 전체 Vitest `39 files / 97 tests` 통과, `tsc -b` 통과,
  production build 통과. Chrome 검증: 격리 DB에 nmap XML로 만든 스캔(#1, SSH·SMB
  관찰 2건 포함)을 Scan Center에서 열어 도구 선택·프로필 구성·명령 미리보기·현재
  스캔 상태(완료)·자동 증적 처리 안내·스캔 대기열/이력 목록·관찰 테이블·artifact
  패널·저장된 출력까지 전부 정상 렌더링 확인, console error 없음.
- runbooks 라우터 분리 후: `python3 -m py_compile`로 변경 파일 전체 통과,
  전체 backend suite `125 passed in ~30s`. FastAPI 앱 기동 확인 및
  OpenAPI 경로 수 대조(원본 33개 route 데코레이터 = 분리 후 31개 unique path,
  GET/POST가 같은 경로를 공유하는 2곳만큼 차이 — 정상). Chrome에서 Runbooks
  페이지 진입 시 builtin SSH runbook 인스턴스가 정상 조회되고(workflow 라우터),
  단계 상태를 "진행 중"으로 저장하면 `PATCH /api/runbooks/steps/1` 200 OK와
  함께 UI가 즉시 갱신됨을 확인(execution 라우터). `GET /credentials?project_id=1`
  응답 확인(credentials 라우터). console error 없음.
- `git diff --check`: 통과

## 다음 작업

1. system status를 작은 system 모듈로 이동하고 정적 프런트 제공은 앱 조립에 유지한다.
2. (선택) `ScanCenter.tsx`에 남은 관찰 테이블/필터/통계와 artifact·터미널 출력
   영역을 추가로 분리할 수 있다 — 필수는 아님.

## 주의점

- Alembic 최신 순서는 `0027_masscan_profiles` → `0028_post_exploitation`이다.
- `models.py` 분리는 SQLAlchemy 등록과 순환 import 위험 때문에 마지막에 검토한다.
- 명령 실행 승인, loopback 제한, 경로 검증과 OSCP 정책 경계는 약화하지 않는다.
- 이 파일은 장기 작업 일지가 아니다. 완료된 세부 내역은 `docs/WORKLOG.md`로 옮기고
  여기에는 다음 도구가 바로 작업을 재개하는 데 필요한 내용만 남긴다.
