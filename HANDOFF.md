# Claude Code / Codex Handoff

이 파일은 두 도구가 저장소를 다시 조사하는 비용을 줄이기 위한 짧은 인수인계 문서다.
의미 있는 구현을 마칠 때마다 작업한 도구가 **현재 상태**, **검증**, **다음 작업**을
갱신한다. 상세한 과거 기록은 `docs/WORKLOG.md`, 설계 원칙은
`docs/ARCHITECTURE.md`, 제품 용어는 `CONTEXT.md`를 참고한다.

## 현재 상태

- 브랜치: `phase-8/stabilization`
- 최근 커밋:
  - `c118cc1` — `WebWorkspace.test.tsx`의 실제 레이스 컨디션 수정(Responder IP
    삽입 테스트 2건, 타이핑이 draft 리셋 effect와 경쟁하던 문제)
  - `915a828` — Vitest pool을 `forks`로 전환(테스트 파일 간 완전한 프로세스 격리)
  - `4c4ec90` — 프로젝트 미선택 시 첫 프로젝트로의 폴백을 localStorage에
    영속화해 헤더/본문 불일치 수정
  - `b44fd07` — `GraphWorkspace.tsx` 2,112 → 479줄 모듈화 (graphModel/
    graphStyles/graphLeaves/OutlineView/GraphCanvas/Inspector/
    GraphRequestPanel)
  - `bbdcc67` — Playwright golden-path E2E 스펙 추가
  - `9eeafb1` — 백엔드 golden-path 통합 테스트 추가
  - `04335c1` — 문서 정합성 수정 (카탈로그 개수, ARCHITECTURE.md 모듈 표)
- 세부 이력은 `docs/WORKLOG.md`의 "Phase 11" 참고.
- 원칙: URL, 요청/응답 형식, DB 스키마를 유지하며 작은 단계로 파일만 분리한다.

## 검증

- 전체 backend suite: `416 passed` (golden-path 통합 테스트 포함)
- 전체 frontend Vitest: `86 files / 401 tests` 통과 (연속 실행으로 결정성 확인)
- `tsc -b`, Vite production build 통과
- `./scripts/test-e2e.sh` (Playwright golden-path): 통과
- Chrome 라이브 확인: `localStorage`의 `oscp-workspace-project`를 비운 상태에서도
  헤더와 Progress Graph 본문이 같은 프로젝트를 가리키는지 확인(수정 전에는
  본문만 온보딩 화면으로 빠졌음)

## 다음 작업

이전 로드맵 항목은 모두 끝났다. 급하지 않지만 다음에 손대기 좋은 후보:

1. (선택) 백엔드 `modules/exploit_research/router.py`(729줄) — 후보 조사/PoC
   import/실행 기록 경계로 나눌 수 있다.
2. (선택) 프런트 `ExploitResearchWorkspace.tsx`(702줄), `RunbookWorkspace.tsx`
   (673줄) — 아직 단일 파일이다.
3. (선택) `ScanCenter.tsx`에 남은 관찰 테이블/필터/통계와 artifact·터미널 출력
   영역.
4. `task_85f2e15e`(Activity Stream 패널이 좁게 눌리는 버그)로 스폰해뒀던
   건은 재조사 결과 재현 불가로 판명됐다 — 새 브라우저 탭에서는 정상 렌더링됐고
   극단적 저장값으로도 clamp 로직이 정상 복구함. 원래 증상은 리팩터링 세션 중
   HMR을 15회 넘게 거친 낡은 탭 자체의 손상 상태였던 것으로 결론. 대신 조사
   과정에서 발견한 실제 버그(프로젝트 폴백 미영속화)는 `4c4ec90`으로 수정됨.

## 주의점

- Alembic 최신 순서는 `0027_masscan_profiles` → `0028_post_exploitation`이다.
- `models.py`(726줄) 분리는 SQLAlchemy 등록과 순환 import 위험 때문에 마지막에
  검토한다.
- 명령 실행 승인, loopback 제한, 경로 검증과 OSCP 정책 경계는 약화하지 않는다.
  Playwright E2E는 반드시 non-root 백엔드로만 구동한다
  (`frontend/e2e/global-setup.ts`).
- `frontend/vitest.config.ts`를 `vite.config.ts`와 `mergeConfig`하지 말 것 —
  cross-file 테스트 격리가 깨진 전례가 있다(Phase 11 참고). `test.exclude`만
  독립적으로 유지한다.
- 이 파일은 장기 작업 일지가 아니다. 완료된 세부 내역은 `docs/WORKLOG.md`로 옮기고
  여기에는 다음 도구가 바로 작업을 재개하는 데 필요한 내용만 남긴다.
