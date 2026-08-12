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
- Progress Graph의 project-root는 `ProjectOperatorSession` 라우터, host는 target-bound
  `ScanCenter`, service는 `ServiceCommandSession`으로 연결된다. 서비스 화면의 기본 작업
  문법은 Context → editable argv → review → attached stdout/PTY이며 기존 프로토콜 도구는
  접힌 toolbox에 보존했다.
- Scan/Service 명령 override는 서버에서 engine·target·port·shell operator drift를 다시
  검증한다. detached terminal의 `[ 원위치 ]`는 detach 전 graph hash와 선택 노드로 복귀한다.
- `DetachableTerminal` seam으로 Scan뿐 아니라 Graph Execution, Service attached output,
  Tools, Hash Cracking, Post-Exploitation, 실제 PTY도 헤더 drag로 전역 floating할 수 있다.
  resize는 window-level pointer tracking과 우측·하단·모서리 grip을 사용하므로 포인터가
  grip 밖으로 나가도 계속되며, 다른 workspace로 이동해도 floating 출력이 유지된다.
- 플로팅 결과는 잘린 header preview 대신 출력 바로 위에 전체 실행 명령을 표시한다.
  Target 컨텍스트가 있는 Scan/Graph/Service/Tools/Hash/Post 결과에는 하단 operator prompt가
  나타나며, 명령 제출 시 target/service-bound bare Bash session을 열어 실제 xterm PTY로
  전환한다. 전환 뒤에는 xterm 자체가 계속 키보드 입력을 받는다.
- Progress Graph에 `🔑 ACCESS LINEAGE` overlay가 추가됐다. 완료·exit 0인
  SSH/WMIExec/WinRM/secretsdump RemoteExecution만 Credential→목적 host 재사용 edge와
  획득 host→목적 host Lateral Access edge로 자동 투영한다. Credential은 계정·유형 badge,
  lineage는 amber/cyan 방향 화살표로 표시하며 secret은 노출하지 않는다. 다른 Target에서
  획득한 같은 Project Credential도 Post-Exploitation 실행에 사용할 수 있다.
- Scan, Service, Graph Execution의 raw stdout은 IP·URL·`80/tcp open http`를 underline
  Candidate로 표시한다. 클릭/우클릭 메뉴에서 승인해야만 child Graph node 생성,
  브라우저 열기, ferox/ffuf staging이 실행되며 오탐 Candidate는 자동 저장되지 않는다.
- Progress Graph 상단에 Time-Machine playhead가 추가됐다. Graph 변경은 동일 fingerprint를
  제거한 append-only `GraphEvent` snapshot으로 누적되며, 과거 frame은 READ ONLY로 잠근다.
  선택 frame은 프로젝트별로 복원되고 `RETURN LIVE` 뒤에만 실행·편집을 재개할 수 있다.

## 검증

- 전체 backend suite: `431 passed` (golden-path 통합 테스트 포함)
- 전체 frontend Vitest: `91 files / 424 tests` 통과
- `tsc -b`, Vite production build 통과
- `npm run test:e2e` (Playwright golden-path): `1 passed`; 래퍼 스크립트는 브라우저
  재설치 단계의 interactive sudo 때문에 이 환경에서 실행하지 못했지만 설치된 Chromium을
  사용한 동일 golden-path는 통과했다.
- Chrome 라이브 확인: Graph의 `제품·버전 식별` Execution 결과를 분리하고
  `608×293 → 748×383` resize, frame 저장, Evidence 이동 후 유지까지 확인했다.
- Chrome 라이브 확인: Scan #29를 floating한 뒤 전체 Nmap 명령 노출, 하단 prompt에서
  `echo FLOAT_PTY_OK` 실행, 실제 Bash PTY의 명령 echo·stdout·다음 prompt까지 확인했다.
- Chrome 라이브 확인: 두 host·Credential fixture에서 `CORP\\administrator · WMIEXEC`,
  `LATERAL · CORP\\administrator` 방향 edge와 `HASH · CAPTURED` badge 렌더를 확인했고
  secret hint가 Canvas draw stream에 포함되지 않는 것도 검증했다.
- Chrome 라이브 확인: Graph Execution stdout의 `80/tcp open http`를 클릭해 Smart Action
  menu와 Graph/browser/ferox·ffuf action을 확인했다. Time-Machine 이전 frame에서 node 수가
  `5→3`으로 복원되고 READ ONLY 잠금, reload 후 frame 복원, LIVE 복귀까지 확인했다.
- Chrome 라이브 확인: `localStorage`의 `oscp-workspace-project`를 비운 상태에서도
  헤더와 Progress Graph 본문이 같은 프로젝트를 가리키는지 확인(수정 전에는
  본문만 온보딩 화면으로 빠졌음)

## 다음 작업

이전 로드맵 항목은 모두 끝났다. 급하지 않지만 다음에 손대기 좋은 후보:

1. (선택) HTTP/SMB 등 protocol toolbox의 legacy 폼도 main
   `ServiceCommandSession`에서 모두 대체 가능한지 확인한 뒤 단계적으로 제거한다.
2. (선택) 백엔드 `modules/exploit_research/router.py`(729줄) — 후보 조사/PoC
   import/실행 기록 경계로 나눌 수 있다.
3. (선택) 프런트 `ExploitResearchWorkspace.tsx`(702줄), `RunbookWorkspace.tsx`
   (673줄) — 아직 단일 파일이다.
4. (선택) `ScanCenter.tsx`에 남은 관찰 테이블/필터/통계와 artifact·터미널 출력
   영역.
5. `task_85f2e15e`(Activity Stream 패널이 좁게 눌리는 버그)로 스폰해뒀던
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
