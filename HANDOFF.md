# Claude Code / Codex Handoff

이 파일은 두 도구가 저장소를 다시 조사하는 비용을 줄이기 위한 짧은 인수인계 문서다.
의미 있는 구현을 마칠 때마다 작업한 도구가 **현재 상태**, **검증**, **다음 작업**을
갱신한다. 상세한 과거 기록은 `docs/WORKLOG.md`, 설계 원칙은
`docs/ARCHITECTURE.md`, 제품 용어는 `CONTEXT.md`를 참고한다.

## 현재 상태

- 비루프백·다중 프로젝트 smoke와 Evidence 딥링크(2026-09-26): Kali 자신의
  `10.0.2.15`에 임시 HTTP 서버를 바인딩하고 격리 DB에 프로젝트 2/Target 2를 만든 뒤
  curl·ffuf를 실행했다. Evidence 9·10번은 프로젝트 2/Target 2에만 저장됐고
  기존 루프백 Evidence 7·8번은 프로젝트 1/Target 1에 유지됐다. 두 새 파일은 API
  다운로드 SHA-256이 DB와 일치하고 Finding은 0건이다. 브라우저 첫 세션에서
  `#evidence/2/10` 링크가 `#graph`로 덮이던 버그를 수정하고 Root/Inspector
  테스트 43개와 프런트 빌드를 통과했다. smoke corpus는 744,112 raw events와
  누적 loss_before 3,743이며 수동 sync가 17.9초 걸렸다. 다음 성능 작업은
  이 전체 corpus 조회 비용을 프로파일링해 줄이는 것이다.
- passive Evidence UI 연결(2026-09-26, `224e081`, `5db4364`): Evidence API에
  `source_type`/`source_id` 필터를 추가하고 Graph의 터미널 활동 상세에서 해당 활동의
  증거 목록·다운로드·`#evidence/{targetId}/{evidenceId}` 이동을 제공한다. Evidence
  화면에서 passive 출처를 "터미널 수집"으로 표시한다. Kali 격리 DB의 ffuf/curl 증거
  7·8번은 목록·미리보기·다운로드 HTTP 200이었고 출처 필터가 각 1건을 반환했다.
  백엔드 Evidence 테스트 17개, 프런트 Inspector 테스트 41개와 빌드가 통과했다.
  backend는 `ShadowTrace-live-release-7`(PID 310957)로 재시작했다. root observer는
  코드 변경이 없어 release-6(PID 298467)에서 계속 실행 중이다.
- curl 출력 증거 후속 작업(2026-09-26, `32014aa`): observer가 curl exec/write/exit를
  passive inbox에 기록한다. 단일 literal HTTP IP URL, 명시적 `-o`/`--output` 파일,
  기존 Target 단일 일치, 파일 소유자·크기·실행 시각이 확인된 경우에만 민감 Evidence를
  만든다. redirect·proxy·다중 URL 등은 unresolved로 남기고 응답 상태·최종 출처나
  Finding은 자동 판정하지 않는다. Kali 관련 테스트 110개 통과. backend와 root observer를
  `ShadowTrace-live-release-6`으로 재시작했고 API 200을 확인했다. 실제 루프백 curl의
  출력 1,010바이트가 PassiveActivity 8번(`observed`, confidence 60)과 Evidence 8번으로
  저장됐다. 원본과 보존본 SHA-256이 같고 보존본 권한은 0600, Finding은 0건이었다.
- ffuf JSON 후속 작업(2026-09-26, `b5d4763`): observer가 ffuf의 exec/stdout/exit를
  passive inbox에 기록하도록 확장했고, backend는 명시한 JSON 출력 파일의 소유자·크기·
  실행 시각을 확인한다. URL의 literal IP가 기존 Target 하나와 일치하고 JSON의 URL도
  동일 대상일 때만 PassiveActivity와 민감 Evidence를 생성한다. Finding과 서비스 관찰은
  자동 생성하지 않는다. Kali 관련 테스트 107개 통과; 실제 ffuf 루프백 JSON을 분리된
  DB에 가져와 결과 1건·Evidence 1건·Finding 0건을 확인했다. backend는
  `ShadowTrace-live-release-5`에서 재시작해 API 200을 확인했다. root observer도 같은
  릴리스에서 재시작했다. 실제 루프백 ffuf 실행이 PassiveActivity 7번(`observed`)과
  민감 Evidence 7번(2,380바이트)으로 자동 저장됐다. JSON 원본과 보존본 SHA-256이
  같고 보존본 권한은 0600, Finding은 0건이었다.
- Passive reconstruction 후속 작업(2026-09-26, `512225e`, `26f9fd3`): 변경 이벤트의 프로세스 계보와 기존
  터미널 세션 구성원만 다시 읽는 증분 경로를 추가했다. 명시적 `ssh host command`의 원격
  명령 인자는 `remote-argv` 미확인 후보로 남기며 Graph 실행 사실로 승격하지 않는다.
  이미 기록된 손실 표시가 새 배치에 반복돼도 전체 이벤트를 다시 재구성하지 않는다.
  Kali 복사 DB의 raw 이벤트 495,398건에서 변경된 실행 이벤트 1건 처리에 0.51초가
  걸렸고 기존 세션·명령 개수는 유지됐다. 손실 표시가 섞인 최근 5,000건의 범위
  선정은 6.9초였다. Kali 관련 테스트 89개 통과, 백엔드 전체 검사에서 624개 통과·2개
  실패했다(timeout 테스트는 단독 재실행 통과, FTP 트리 테스트는 변경 전 커밋에서도
  동일하게 실패). Kali 실행 서버는 `ShadowTrace-live-release-4`의 `26f9fd3`으로 교체했고
  관찰기는 계속 실행 중이다. 실제 `/api/passive/sync`는 24개 배치·1,399개 이벤트를
  약 9.9초에 처리하고 HTTP 200을 반환했다.
- 브랜치: `main` (`ShadowTrace` fork)
- Generic passive sensor foundation: `scripts/passive-observer.py`가 owner UID process
  계보의 fork/exec/exit, fd 0/1/2 I/O, socket lifecycle 일부와 변경형 filesystem
  syscall을 수집한다. versioned raw batch에는 sequence, monotonic/wall time, PID/TTY/cwd,
  namespace/cgroup, capture state, confidence와 loss가 포함되며 `RawActivityEvent`로 멱등
  저장된다. echo-off/불명 input은 내용 없이 redaction marker만 남긴다.
- Raw event는 의미 Graph와 분리돼 있다. 현재 자동 의미 승격은 Nmap MVP만 지원하며
  `PassiveActivity → ScanJob(source=passive) → Observation → Target/Service → Graph`로
  투영한다. 단일 literal IP만 자동 해결하고 Finding은 만들지 않는다. collector가 알린
  truncation/loss는 confidence 60과 partial error로 전파한다.
- Passive Session Reconstruction: raw ingest 뒤 `reconstruct(db)`가 boot/PID/start ticks로
  ProcessInstance를, boot/PID namespace/SID/TTY로 TerminalSession을 구성한다. PGID와
  stdio FD target으로 CommandActivity의 pipeline/redirect/background 후보를 만들고,
  shell builtin과 SSH 내부 입력은 낮은 confidence의 PTY candidate로만 남긴다. local ssh는
  RemoteSessionCandidate를 만들지만 Graph/Observation은 변경하지 않는다.
- 모든 Kali/terminal 활동이나 행동별 Graph node는 보장하지 않는다. `writev`, 임의 FD,
  전체 file write/mmap, raw packet, tmux pane 의미, SSH 원격 background 작업, Burp/browser
  내부 상태와 VM guest는 미포착 또는 불완전하다. 전체 매트릭스와 출처는
  `docs/RESEARCH_PASSIVE_PENTEST_ACTIVITY_COVERAGE.md`에 있다.
- server launcher는 `scripts/start.sh` 하나로 통합됐다. non-root 환경·migration·sudo
  전환과 root observer/uvicorn lifecycle을 같은 파일이 담당하고, `dev.sh`는
  `start.sh --reload`를 재사용한다.
- 최근 커밋:
  - `b00850a` — 전수 감사로 찾은 버그 6건 수정(각각 pre-fix 코드에서 실패하는
    회귀 테스트 포함): tunnels `create_tunnel`이 sync 라우트라
    `asyncio.create_task()`가 매번 RuntimeError로 죽어 SSH 터널이 한 번도
    작동한 적이 없던 문제, `InteractiveSession.graph_parent_node_id`가
    technique 타입 가드 누락으로 `/graph/sync` 전체를 깨뜨리던 문제,
    dismissed host 아래 service 노드가 sync에서 영구히 스킵되던 문제,
    `delete_node`가 `pinned_canonical_edge_id` 정리를 안 하던 문제,
    Command Palette로 다른 프로젝트 서비스 선택 후 전환 시 헤더/본문
    불일치, `WebWorkspace` draft가 무관한 background refetch로 사라지던
    문제, 죽은/leak되는 localStorage 핸드오프 정리.
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

- 전체 backend suite `604 passed`(repository venv site-packages와 loopback 통합 테스트
  포함). reconstruction/passive targeted `24 passed`, migration `4 passed`. Alembic
  `0045_session_reconstruction` fresh/contaminated upgrade, Python compile, shell syntax와
  diff check 통과.
- 2026-09-26 Kali VM에서 현재 커널 `6.19.14+kali-amd64`의 matching headers와 BCC를
  확인했고 root BPF observer를 실제 load했다. `passive-live-smoke.py`는 해당 프로세스
  이벤트 264개, 모든 필수 kind와 truncation을 확인해 통과했다. 터미널 2개·tmux pane
  2개는 각기 다른 session에 `sleep` 명령이 붙었고 local interactive SSH는
  `RemoteSessionCandidate` 1건이 됐다. 관련 backend targeted `89 passed`.
- 자동 observer sync와 수동 sync가 겹칠 때 관찰된 HTTP 500에 대해 router의 sync/reconstruct
  직렬화를 추가했다. 회귀 테스트는 수정 전 실패, 수정 후 통과. 최신 코드로 별도 포트에서
  같은 batch의 동시 요청을 보내 모두 HTTP 200을 확인했다. 후속 작업에서 커널 exec
  `comm` 보존·monotonic 재정렬·부모 PTY 상속과 PTY redaction gap 폐기를 추가했다.
  실제 Kali에서 argv를 놓친 짧은 `/usr/bin/true` 30건 모두 `kernel-comm` 출처,
  낮은 confidence의 `true` 명령으로 복원됐다. Graph 노드 5개는 그대로였고
  새 host/project claim은 없었다. 상세 내용은
  `docs/PASSIVE_SESSION_RECONSTRUCTION.md`에 있다.
- 이전 원본 기준 backend suite: `542 passed` (golden-path 통합 테스트 포함)
- 전체 frontend Vitest: `95 files / 497 tests` 통과
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

Passive reconstruction의 다음 필수 단계:

- 실제 대화형 SSH self-loopback 입력은 OpenSSH의 별도 PTY fd/ECHO-off 때문에
  `remote-input`으로 수집되지 않음을 확인했다. 로컬 SSH client와
  RemoteSessionCandidate만 남는다. 원격 명령 성공을 추측하거나 ECHO-off 입력을
  수집하지 않는다. 동시에 183,442 raw event corpus에서 sync가 20초 이상 걸리는
  병목을 발견해 late start-tick remap의 과거 이벤트 반복 순회를 alias 일괄 해소로
  바꿨다. `_processes()` 동일 corpus 14.366→8.681초, 19개 reconstruction 테스트와
  Kali backend 622개 테스트 통과(MongoDB 2개 모듈 제외). 여전히 전체 raw corpus
  로드/정렬은 남은 확장성 과제다.
- 실제 펜테스팅 흐름 감사에서 Nmap `-oX -`의 XML stdout이 raw로만 남고 서비스로
  승격되지 않는 문제를 Kali loopback에서 재현했다. `-oN`은 stdout 포트 표가 있어
  같은 증상이 없었다. XML stdout과 안전하게 검증된 `-oA`/`-oX` XML 파일을 기존
  Scan Center 파서로 가져오고, XML·stdout을 별도 Evidence로 남기도록 수정했다.
  실제 XML stdout 스캔은 `observed`, 서비스 product `Uvicorn`, Finding 0건.
  후속 `-oA` 루프백 스캔에서는 XML·stdout 각각 ScanArtifact/Evidence 1건,
  product 유지, Finding 0건을 확인했다. 운영 DB의 `autoflush=False`에서 stdout
  Evidence가 누락되던 오류도 flush 추가와 회귀 테스트로 수정했다.
  관련 30 tests, MongoDB 2개 모듈을 제외한 backend 621 tests 통과.

1. ffuf/curl의 원시 수집·loopback 귀속 smoke는 확인했다. 더 긴 관찰기 연속 실행과
   비루프백 다중 프로젝트 귀속을 검증한다. 36k corpus full rebuild 7.8초,
   idle sync 0.065초, 30초 batch·서버 PID 제외 후 5초 평균 backend CPU 0.4%.
   실측 중 BCC perf loss callback 서명 오류를 발견해 손실 카운트가 기록되도록 고쳤다.
2. ffuf/curl/Burp semantic parser 추가 전 응답 artifact와 실제 대상 귀속 품질을
   각각 검증한다. 원시 명령을 의미 있는 finding으로 자동 승격하지 않는다.
   실측 Graph sync에서 단일 프로젝트만 있다는 이유로 생성된 command_activity 노드
   66개를 발견해 fallback을 제거했고, 재동기화로 71→5개 노드가 되어 명시적 Nmap
   capture만 남았다.

그 이후 선택 후보:

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
