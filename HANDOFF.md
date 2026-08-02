# Claude Code / Codex Handoff

이 파일은 두 도구가 저장소를 다시 조사하는 비용을 줄이기 위한 짧은 인수인계 문서다.
의미 있는 구현을 마칠 때마다 작업한 도구가 **현재 상태**, **검증**, **다음 작업**을
갱신한다. 상세한 과거 기록은 `docs/WORKLOG.md`, 설계 원칙은
`docs/ARCHITECTURE.md`, 제품 용어는 `CONTEXT.md`를 참고한다.

## 현재 상태

- 브랜치: `phase-8/stabilization`
- 최근 커밋:
  - `64ba3f0` — runbooks 라우터를 workflow/execution/credentials로 분리
  - `bd86601` — ScanCenter를 tool/profile/job-status/history로 분리
  - `aadfbe6` — App.tsx의 psexec 권한상승/실시간 출력 영역 분리
- **`main.py`/`App.tsx`/`ScanCenter.tsx`/`runbooks` 대형 파일 모듈화 로드맵이
  이번 세션에서 모두 완료됐다.** 세부 이력은 `docs/WORKLOG.md`의
  "Phase 10 — Backend/frontend modularization (stabilization)" 참고.
- 원칙: URL, 요청/응답 형식, DB 스키마를 유지하며 작은 단계로 파일만 분리한다.

## 이번 세션 요약

- 백엔드: `main.py` 562줄 → 139줄. system status를
  `backend/app/modules/system.py`로 이동(TOOLS 딕셔너리 포함). 정적 프런트
  제공과 lifespan은 `main.py`에 유지.
- 백엔드: `runbooks/router.py` 1,185줄 → `support.py` + `workflow_router.py` +
  `execution_router.py` + `credentials_router.py` 4개 파일로 분리. 세 라우터
  모두 `/api/runbooks` prefix를 공유해 URL은 그대로다.
- 프런트엔드: `App.tsx` 2,062줄 → 1,110줄. `ScanCenter.tsx` 1,131줄 → 603줄.
  둘 다 여러 단계로 나눠 각 컴포넌트/모듈에 독립 테스트를 추가했다.

## 검증

- 전체 backend suite: `125 passed`
- 전체 frontend Vitest: `39 files / 97 tests` 통과
- `tsc -b`, Vite production build 통과
- Chrome 스모크: Scan Center, Service Enumeration, Runbooks에서 격리 DB
  (`/tmp/oscp-browser-validation`)로 실제 데이터 흐름 확인. Runbooks는
  `PATCH /api/runbooks/steps/{id}` 실제 왕복까지 확인. console error 없음.
- `git diff --check` 통과

## 다음 작업

이전 로드맵 항목은 모두 끝났다. 남은 대형 파일은 급하지 않지만, 다음에 손대기
좋은 후보:

1. (선택) 백엔드 `modules/exploit_research/router.py`(729줄) —
   후보 조사/PoC import/실행 기록 경계로 나눌 수 있다.
2. (선택) 프런트 `ExploitResearchWorkspace.tsx`(702줄), `RunbookWorkspace.tsx`
   (673줄) — 아직 단일 파일이다.
3. (선택) `ScanCenter.tsx`에 남은 관찰 테이블/필터/통계와 artifact·터미널 출력
   영역.

이 중 어느 것도 이전 대상들(1,100줄 이상)만큼 크지 않으므로, 사용자가 다른
기능 작업을 우선하고 싶다면 이 목록은 미뤄도 된다.

## 주의점

- Alembic 최신 순서는 `0027_masscan_profiles` → `0028_post_exploitation`이다.
- `models.py`(726줄) 분리는 SQLAlchemy 등록과 순환 import 위험 때문에 마지막에
  검토한다.
- 명령 실행 승인, loopback 제한, 경로 검증과 OSCP 정책 경계는 약화하지 않는다.
- 이 파일은 장기 작업 일지가 아니다. 완료된 세부 내역은 `docs/WORKLOG.md`로 옮기고
  여기에는 다음 도구가 바로 작업을 재개하는 데 필요한 내용만 남긴다.
