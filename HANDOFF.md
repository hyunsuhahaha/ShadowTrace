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
- `git diff --check`: 통과

## 다음 작업

1. 프런트엔드 `App.tsx`에서 실행 이력 화면 영역을 다음 작은 seam으로 분리한다.
2. system status를 작은 system 모듈로 이동하고 정적 프런트 제공은 앱 조립에
   유지할지 검토한다.
3. 프런트엔드는 `App.tsx`, `ScanCenter.tsx` 순서로 상태와 화면을 분리한다.

## 주의점

- Alembic 최신 순서는 `0027_masscan_profiles` → `0028_post_exploitation`이다.
- `models.py` 분리는 SQLAlchemy 등록과 순환 import 위험 때문에 마지막에 검토한다.
- 명령 실행 승인, loopback 제한, 경로 검증과 OSCP 정책 경계는 약화하지 않는다.
- 이 파일은 장기 작업 일지가 아니다. 완료된 세부 내역은 `docs/WORKLOG.md`로 옮기고
  여기에는 다음 도구가 바로 작업을 재개하는 데 필요한 내용만 남긴다.
