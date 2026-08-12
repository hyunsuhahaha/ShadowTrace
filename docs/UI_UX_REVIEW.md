# Graph UI/UX 검토 — BloodHound / NodeZero 대비

> 2026-08-13 작성. `frontend/src/features/graph/`의 현재 구현을 코드 근거로 정리하고,
> BloodHound(순수 노드-엣지 AD 관계 시각화)와 NodeZero(좌→우 타임라인 + 자동화
> 침투 결과 UI)에서 우리 Progress Graph에 참고할 만한 요소를 검토한다. **이 문서는
> 검토·제안까지만 하며 UI 코드를 수정하지 않는다.**
>
> **원칙**: 이 프로젝트는 사람이 직접 실행하고 승인한 것만 기록한다(`CONTEXT.md`,
> `docs/OSCP_POLICY.md`). NodeZero의 "자동화 엔진이 실행한 로그를 재현하는" 요소
> (자동 진행 타임라인 애니메이션, 자동 검증 PROOF 배지)는 후보에서 제외했다.
> 개념 자체가 쓸모 있어 보이는 경우(PROOF 배지 등)에도 "사람이 승인/첨부한 시점"
> 기준으로 재해석했다 — §3, §5 참고.

## 1. 현재 Graph 뷰가 보여주는 것

`frontend/src/features/graph/`(`GraphCanvas.tsx` 698줄, `graphModel.ts` 265줄,
`GraphWorkspace.tsx` 533줄, `Inspector.tsx` 297줄, `OutlineView.tsx`,
`GraphTimeMachine.tsx` 등)을 코드 기준으로 정리하면 이미 상당히 풍부하다.

### 1.1 노드 렌더링
아이콘 폰트/SVG 시스템은 없고, 타입별 유니코드 글리프 1글자를 캔버스 텍스트로
그린다(`graphModel.ts:64-67`):

```
project-root ◎  operator ⌁  host ▣  service ◉  finding ◇  technique ⚡  credential 🔑
```

색은 타입이 아니라 **상태**(`GraphNode.status`)로 결정된다(`STATUS_COLOR`,
`graphModel.ts:43-46`: untried 회색 / in-progress 주황 / attempt-failed 빨강 /
succeeded 초록 / blocked 보라 / not-applicable 짙은 회색). 크기는 역할별로 3단계뿐
(`GraphCanvas.tsx:297`) — root/anchor 40px, host/operator 26px, 나머지(service/
finding/technique/credential)는 전부 19px 동일. credential 노드만 원이 아니라
호박색 테두리의 사각 배지로 그려진다(`GraphCanvas.tsx:299-322`).

### 1.2 상태·특수 표시
상태는 채우기 색·테두리·글로우로만 표현되고 별도 배지 모양은 없다. 예외 두 가지:
`awaitingReview`(실행은 끝났지만 사람 검토 대기)는 원을 속이 빈 링으로 그리고
(`GraphCanvas.tsx:293, 386`), objective 노드는 금색 외곽 링 하나가 추가된다
(`GraphCanvas.tsx:376-380`, Inspector에 "🎯 목표" 라벨도 표시 — `Inspector.tsx:138`).
숨긴 노드는 투명도 0.3 + 점선 테두리(`GraphCanvas.tsx:298, 395`).

### 1.3 엣지 렌더링
"구조적" 관계(`discovered, enumerated, attempted, yielded, pivoted-to, operates,
runs` — `GraphCanvas.tsx:80-81`)는 실선 직선, 그 외(수동 추가 엣지 포함)는 곡선 +
점선(`GraphCanvas.tsx:226-231`). **화살표는 두 관계에만 있다** — `captures-from`
(빨간 삼각형 + "AUTH CAPTURE" 라벨, `GraphCanvas.tsx:247-256`)와 Access Lineage
엣지 두 종류(§1.4). 그 밖의 모든 엣지는 방향 표시가 없다.

### 1.4 Access Lineage 오버레이 (🔑)
완료·exit 0인 SSH/WMIExec/WinRM/secretsdump 실행에서 `reused-credential`(호박색)과
`pivoted-to`(청록색, `status==="succeeded"`일 때만) 엣지를 idempotent하게 투영하고,
화살표 + "CREDENTIAL REUSE"/"LATERAL ACCESS" 라벨 핀을 그린다(`GraphCanvas.tsx:
223-225, 258-279`). 저장된 secret 값 자체는 그리지 않는다.

### 1.5 활동/생존 표시
`meta.activity`(scan/execution/listener × queued/running/processing/launched)를
읽어 초록(스캔)·빨강(리스너)·파랑(연결됨) 신호색으로 레이더 펄스(최대 3중 확장
링) + 회전 스윕 웨지 + 캡션 배지("SCANNING"/"LISTENING" 등)를 그린다
(`GraphCanvas.tsx:99-118, 323-368, 415-426`). 활성 엣지는 진행 방향으로 흐르는
발광 점("packet")을 그린다(`GraphCanvas.tsx:238-246`). `prefers-reduced-motion`을
존중한다.

### 1.6 시간/연대기
캔버스 안에는 좌→우 타임라인이나 경과시간 카운터가 없다. 시간은 두 군데에서만
보인다.
- **Activity Stream**(우하단 플로팅 패널, `GraphCanvas.tsx:543-698`): `[HH:MM:SS]`
  벽시계 시각이 붙은 최신순 스크롤 목록.
- **Graph Time-Machine**(`GraphTimeMachine.tsx`): 연속 타임라인이 아니라 **이산
  스냅샷 스크러버**다 — `GraphEvent`(있으면) 또는 node/edge `created_at`을 프레임
  단위로 모아 슬라이더/◀▶/재생(700ms 간격)으로 넘기고, "{n}/{total} EVENTS"를
  보여준다(`GraphTimeMachine.tsx:7-89`).

### 1.7 레이아웃 모드
force-directed graph / tree(깊이별 컬럼 배치) / outline(들여쓰기 DOM 트리) 3모드가
있고(`GraphWorkspace.tsx`의 `view` state, `oscp-graph-view`에 유지), **phase 링**은
graph 모드에서만 anchor 노드를 중심으로 한 5개의 동심원(DISCOVERY→EVIDENCE, 반지름
70+58×i, 옅어지는 초록)으로 그려진다(`GraphCanvas.tsx:199-211`) — 노드를 단계별로
분류해서 배치하는 게 아니라 배경 장식용 링일 뿐이다.

### 1.8 노드 상세
project-root/host/service 노드는 Inspector 대신 **해당 화면 자체가 통째로
임베드**된다(`GraphWorkspace.tsx:476-492`: project-root→`ProjectOperatorSession`,
host→`ScanCenter`, service→`App.tsx`). finding/credential/technique만 작은
`Inspector.tsx` 카드(제목·상태 버튼·메모)를 쓰고, finding/credential은 거기서 다시
`ReportWorkspace`/`PostExploitationWorkspace`/`HashCrackingWorkspace`를 딥링크로
그래프 밖으로 나가지 않고 연다. 호버/선택 요약(`nodeSummary()`, `graphModel.ts:
81-103`)은 finding에 한해 이미 `severity`와 `evidence {count}`를 보여준다.

### 1.9 Terminal Candidate
`SmartTerminalOutput.tsx`가 stdout에서 IP/URL/서비스를 파싱해 밑줄 토큰으로만
표시하고(`smart-terminal.css`, 경고색 밑줄), 우클릭 메뉴의 "＋ ADD AS CHILD NODE"를
사용자가 직접 눌러야만 그래프 노드가 생긴다 — 파싱·하이라이트 자체는 그래프를
수정하지 않는다(`SmartTerminalOutput.tsx:73-165`).

## 2. BloodHound에서 참고할 요소

BloodHound의 핵심은 "이 계정에서 Domain Admins까지 최단 경로"처럼 **선택한 두 점
사이의 공격 경로를 하이라이트**하는 것이다. 우리 그래프는 이미 `objective`/
`objective_kind` 필드(`graphModel.ts:11`, `GraphCanvas.tsx:376-380`)로 "목표 노드"
개념이 있지만, 그 목표까지의 **경로를 찾아 강조하는 로직은 없다** — 현재는 시각적
장식(금색 링)뿐이다. 이걸 실제 경로 탐색으로 확장하는 게 가장 직접적인 이식 후보다.

BloodHound의 다른 특징(Cypher 쿼리 검색, 노드 속성 패널의 "owned/high value" 마킹,
엣지 타입별 필터)은 대부분 이미 우리 쪽에 대응품이 있다 — objective 플래그(owned에
대응), 그래프 작업 바의 라벨/타입/상태 검색·필터(`docs/ENGINEERING_ONBOARDING.md`
§10.14). Cypher 쿼리 같은 임의 그래프 질의어는 1인 수동 워크플로우에 과한 복잡도라
후보에서 뺐다.

## 3. NodeZero에서 참고할 요소 (자동화 로그 재현 제외)

| NodeZero 요소 | 원본 의미 | 우리 워크플로우 재해석 |
|---|---|---|
| PROOF 배지 | 자동화 엔진이 취약점을 "검증"했다는 표시 | **제외 대신 재해석**: "이 노드에 사람이 첨부한 Evidence가 있다"는 배지로. 자동 판정이 아니라 "증거가 붙어 있나"만 보여준다 |
| HOST COMPROMISE 태그 | 엔진이 자동으로 침투 성공을 표시 | 이미 Access Lineage(§1.4)의 `reused-credential`/`pivoted-to` 화살표가 사람이 승인한 실행 결과로만 같은 정보를 보여주고 있어 **중복** — 새로 안 만든다 |
| 좌→우 절대 타임라인 좌표계 | 엔진이 단계를 실행한 순서를 그래프 배치 자체로 표현 | 부분 채택: 새 레이아웃 모드보다는, 이미 있는 Activity Stream/Time-Machine을 보강하는 쪽이 비용 대비 낫다고 판단(§4) |
| 경과 시간 카운터(0:05:17) | 자동 공격 시작 이후 각 단계까지 걸린 시간 | 재해석: "자동 단계별 소요 시간"이 아니라 **프로젝트 생성 이후 경과한 벽시계 시간**(OSCP+ 23시간45분 제한 관리용) — 사람이 보는 수동 표시일 뿐 자동 진행과 무관 |
| 타입별 아이콘(Host/Service/Weakness/RAT/Credential) | 장식적 구분 | 순수 가독성 개선으로만 채택 가능 — 자동화 의미 없음 |
| 실선/점선 엣지 구분 | 확정된 관계 vs 추정 관계 | **이미 있음**(§1.3) — 참고할 필요 없음 |

## 4. 후보 비교표

| 후보 | 데이터 모델로 지금 표현 가능한가 | 구현 난이도 | 실사용 워크플로우 도움 vs 장식 |
|---|---|---|---|
| **Evidence-backed 배지를 모든 노드 타입으로 확장** | Host/Service는 `Evidence.target_id`/`service_id`로 finding과 똑같은 count 쿼리(`graph/service.py:438-442` 패턴 그대로) 재사용 가능. Credential은 Evidence에 직접 FK가 없지만, 방금 §5-2에서 만든 `Credential.source_execution_kind`+`source_execution_id` → `RemoteExecution`/`HashCrackJob.evidence_id` 체인을 타면 새 필드 없이 가능 | 중간 (백엔드 sync 쿼리 확장 + 프론트 배지 렌더) | **도움 큼** — OSCP 보고서는 주장마다 근거가 있어야 하는데, "이 노드 주장에 Evidence가 붙어 있나"를 그래프에서 바로 보이면 보고서 작성 전 스캔이 쉬워진다 |
| **Path-to-Objective 하이라이트** | `objective`/`objective_kind` 필드는 이미 있음(§2). 경로 탐색(BFS)과 하이라이트 렌더만 새로 필요 | 중간 (프론트 그래프 탐색 알고리즘 + edge 강조 렌더) | **도움 큼** — "지금 가진 걸로 목표까지 어떻게 가지"를 바로 보여줌, BloodHound의 핵심 가치를 그대로 이식 |
| **프로젝트 경과 시간 표시** | `Project.created_at` 이미 존재, 클라이언트 계산만 필요 | 작음 | **도움 중간-큼** — OSCP+ 시간 제한 관리에 실질적, 자동화 원칙과 충돌 없는 순수 수동 표시 |
| **구조적 엣지에도 방향 화살표 추가** | 신규 필드 불필요, 렌더 로직만 확장 | 작음 | **도움 중간** — 현재 대부분의 엣지가 방향 표시가 없어(§1.3) 수동으로 추가한 엣지의 방향이 모호할 수 있음 |
| **타입별 아이콘 업그레이드(글리프→소형 SVG)** | 신규 필드 불필요, 순수 렌더 | 작음 | **장식에 가까움** — 현재 글리프 시스템도 이미 기능은 함, 가독성 개선 정도 |
| 좌→우 타임라인 레이아웃 모드 신설 | `created_at`은 있으나 새 레이아웃 알고리즘 필요 | 큼 | **애매함** — Activity Stream이 이미 연대기 목록을 제공해 기능 중복 우려, 비용 대비 이득 낮음 |
| HOST COMPROMISE류 명시적 배지 신설 | 가능하지만 | 작음 | **장식/중복** — Access Lineage 화살표가 이미 같은 정보를 사람이 승인한 실행 기준으로 보여줌 |

## 5. 제외한 것

- NodeZero의 자동 진행 타임라인 애니메이션(엔진이 단계를 실행하는 것을 재생하는 연출) — 이 프로젝트엔 "엔진이 실행"하는 개념 자체가 없다(사람이 매 실행을 승인). 채택하지 않는다.
- NodeZero의 PROOF 배지를 "자동 검증됨" 의미 그대로 채택 — 위 §3에서 "사람이 Evidence를 첨부했나"로 재해석한 버전만 후보에 남긴다.
- BloodHound의 Cypher 쿼리 검색 — 1인 수동 워크플로우에 비해 과한 복잡도.
- HOST COMPROMISE류 신규 배지 — Access Lineage와 의미가 겹쳐 추가 가치가 낮다.

## 6. 최종 추천 (우선순위 순, 3~5개)

> **[2026-08-13 구현 완료]** 1~4번을 모두 적용했다 — `backend/app/modules/graph/service.py`
> (evidenceCount 동기화), `frontend/src/features/graph/graphModel.ts`(`evidenceCount`/
> `pathToObjective`/`formatElapsed` 순수 함수 + 테스트), `GraphCanvas.tsx`(배지·halo·화살표
> 렌더), `GraphWorkspace.tsx`(🎯 PATH TO OBJECTIVE 토글), `graphLeaves.tsx`(`ElapsedTimer`).
> 백엔드 449 / 프런트엔드 430 테스트 통과, 프로덕션 빌드 클린. 다만 이 세션에서는 공유
> dev 백엔드(포트 8000)가 root 권한으로 떠 있고 응답이 없어(연결된 VPN을 보면 실제 대상
> 스캔 중일 가능성이 있어 건드리지 않음) 브라우저 실사용 확인은 못 했다 — 직접 화면에서
> 한 번 확인해 보는 걸 권장한다. 5번(아이콘 SVG 업그레이드)은 여전히 미착수.

1. **Evidence-backed 배지를 모든 노드 타입으로 확장.** 보고서 작성과 가장 직접
   연결되고, host/service는 finding과 동일한 쿼리 패턴을 재사용하면 되며 credential은
   최근에 추가한 `source_execution_kind`/`source_execution_id` 체인이 그대로
   전제조건을 채워준다.
2. **Path-to-Objective 하이라이트.** BloodHound의 핵심 가치를 그대로 가져오는
   기능이고, 필요한 데이터(objective 플래그, 엣지)가 이미 있어 새 스키마 없이
   프론트 탐색 로직만 추가하면 된다.
3. **프로젝트 경과 시간 표시.** 구현 비용이 가장 낮고, OSCP+ 시험 시간 제한이라는
   이 프로젝트의 실제 사용 맥락에 직접 맞아떨어진다.
4. **구조적 엣지에도 방향 화살표 추가.** 현재 대부분의 엣지에 방향 표시가 없다는
   구체적인 가독성 구멍을 낮은 비용으로 메운다.
5. *(선택, 미착수)* **타입별 아이콘을 소형 SVG로 업그레이드.** 순수 가독성 개선이라
   우선순위는 낮지만, 4번과 묶어서 같은 PR에서 처리하면 비용이 크지 않다.

좌→우 타임라인 레이아웃과 HOST COMPROMISE류 배지는 후보로 검토했지만 기존 기능과
중복되거나 비용 대비 이득이 낮아 이번 추천에서 뺐다 — §4 표 참고.
