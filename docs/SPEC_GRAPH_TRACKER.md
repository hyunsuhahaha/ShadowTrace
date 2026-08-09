# 명세서: 진행상황 그래프 트래커 (Progress Graph Tracker)

- 상태: Draft v1 (구현 착수 가능 수준)
- 대상 스택: 기존 OSCP Workspace (FastAPI + SQLite 백엔드, React/Vite + TypeScript 프론트)
- 배치: `backend/app/modules/graph`, `frontend/src/features/graph`
- 범위: 허가된 랩/연습 환경의 **개인 진행상황 트래킹** 전용. 실제 시험 세션 사용을 목표로 하지 않는다.

---

## 0. 한 줄 요약

하나의 프로젝트(=하나의 대상 호스트)에 대해 정찰→열거→시도→결과의 흐름을 **단일 그래프**
`(nodes, edges)`로 저장하고, 같은 데이터를 두 방식으로 렌더링한다.

- **Graph 뷰** (force-directed): 탐색용. "어디서 막혔나 / 무엇을 안 해봤나"를 색으로 드러냄.
- **Reference Tree 뷰**: 정리·리포트용. root(최초 nmap 노드)에서 펼친 트리이며, 다중 부모/순환은
  복제하지 않고 `↗ 참조` / `↩ 순환 참조`로 canonical 노드를 가리킨다.

두 뷰는 **같은 데이터**를 공유하고 렌더러만 다르다. 트리 구조는 종료 후 리포트 목차로 그대로 변환된다.

---

## 1. 데이터 모델

### 1.1 설계 원칙

- 단일 그래프. 뷰별로 데이터를 복제하지 않는다.
- **색 = 상태**(status), **모양/아이콘 = 타입**(type)을 기본 인코딩으로 삼는다.
  참고 이미지처럼 "타입별 색"으로 볼 수 있는 대체 모드(color-by-type)도 토글로 제공한다.
  기본이 상태-색인 이유: 트래커의 1차 목적이 "막힌 지점/안 해본 시도"의 즉시 파악이기 때문.
- 그래프는 기존 도메인(Target/Service/Scan/Evidence 등)을 **부분적으로 투영**하고,
  트래커 고유의 오버레이(Attempt/Technique 노드, 시도 결과·크리덴셜 재사용 엣지)를 **추가로 저장**한다.
  즉 기존 엔티티는 `sourceRef`로 역참조하고, 그래프 고유 데이터는 그래프 테이블이 소유한다.

### 1.2 공통 필드 (모든 Node)

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `id` | string (ULID) | ✔ | 전역 고유. ULID는 시간순 정렬성이 있어 tie-break에 유리 |
| `projectId` | string | ✔ | 스코핑 키. 이 값으로 그래프를 격리 |
| `type` | enum `NodeType` | ✔ | `host` \| `service` \| `finding` \| `technique` \| `credential` |
| `label` | string | ✔ | 화면 표시명 (예: `445/tcp smb`, `MS17-010`) |
| `status` | enum `NodeStatus` | ✔ | 아래 1.5. 색 인코딩의 근거 |
| `createdAt` | ISO-8601 datetime | ✔ | **canonical 판정의 기준값**. 최초 발견/시도 시각 |
| `updatedAt` | ISO-8601 datetime | ✔ | 마지막 변경 시각 |
| `sourceRef` | object \| null | – | 기존 도메인 역참조 `{ module, kind, id }` (예: `{module:"scans", kind:"service", id:42}`) |
| `notes` | string (Markdown) | – | 자유 메모. 리포트 서술 원천 |
| `tags` | string[] | – | 자유 태그 (`quick-win`, `rabbit-hole` 등) |
| `pinned` | boolean | – | 레이아웃 고정 여부 (그래프 뷰) |
| `position` | `{x,y}` \| null | – | 수동 배치 좌표 캐시. null이면 시뮬레이션이 결정 |
| `meta` | object | – | 타입별 필드(1.3) |

### 1.3 타입별 `meta`

**host**
| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `ip` | string | ✔ | 대상 IP |
| `hostname` | string | – | 확인된 호스트명 |
| `os` | string | – | 추정/확인 OS |
| `zone` | enum | – | `external` \| `internal` \| `dmz` (pivot 대비) |

**service**
| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `port` | number | ✔ | 포트 번호 |
| `protocol` | enum | ✔ | `tcp` \| `udp` |
| `serviceName` | string | – | `http`, `smb` 등 |
| `product` | string | – | 배너/제품명 |
| `version` | string | – | 버전 |
| `portState` | enum | – | `open` \| `filtered` \| `closed` |

**finding** (관찰된 사실/취약 후보 — 판정 아님)
| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `category` | string | – | 분류(예: `auth`, `injection`, `misconfig`) |
| `cve` | string[] | – | 관련 CVE. 비어 있을 수 있음 |
| `severity` | enum | – | `info`\|`low`\|`medium`\|`high`\|`critical` (사용자 표기) |
| `evidenceRefs` | string[] | – | evidence 모듈 파일 ID 목록 |

**technique** (하나의 구체적 시도/기법)
| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `category` | string | – | `exploit`\|`bruteforce`\|`enum`\|`privesc`\|`lateral` 등 |
| `tool` | string | – | 사용 도구명 |
| `commandRef` | string \| null | – | executions 모듈 실행 ID 역참조 |
| `mitreId` | string \| null | – | 선택. ATT&CK 매핑 |
| `outcomeSummary` | string | – | 결과 한 줄 요약 |

**credential**
| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `username` | string | – | 사용자명 |
| `credType` | enum | ✔ | `password`\|`hash`\|`key`\|`token` |
| `secretRef` | string \| null | – | **평문 저장 금지.** Credential Store(기존 opt-in vault) 참조 ID |
| `secretHint` | string | – | 마스킹 힌트만 표시 |
| `validatedOn` | string[] | – | 검증 성공한 node id 목록(파생 캐시, 엣지가 원천) |

> 보안: credential 노드는 기존 아키텍처의 Credential Store 규칙을 그대로 따른다.
> 평문 비밀은 그래프에 저장하지 않고 `secretRef`만 둔다. 검색/리포트 export에서 비밀은 마스킹한다.

### 1.4 Edge 스키마

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `id` | string (ULID) | ✔ | 고유 |
| `projectId` | string | ✔ | 스코핑 |
| `source` | node id | ✔ | 출발 노드 |
| `target` | node id | ✔ | 도착 노드 |
| `relation` | enum `EdgeRelation` | ✔ | 아래. 관계의 **의미** |
| `status` | enum `EdgeStatus` | ✔ | 시도 상태(색 인코딩). 아래 1.5 |
| `structural` | boolean | ✔(파생) | 트리 골격 후보 여부. `relation`으로 결정(1.6) |
| `createdAt` | ISO-8601 | ✔ | **canonical 판정 기준** |
| `updatedAt` | ISO-8601 | ✔ | – |
| `label` | string | – | 표시용 |
| `meta` | object | – | 관계별 부가정보 |

`EdgeRelation` 값과 방향 규약:

| relation | 방향(source→target) | structural | 의미 |
|---|---|---|---|
| `discovered` | host → service | ✔ | 스캔이 서비스를 발견 |
| `enumerated` | service → finding | ✔ | 열거로 finding 도출 |
| `attempted` | finding → technique | ✔ | finding에 기법 시도 |
| `yielded` | technique → (credential\|host\|service\|finding) | ✔ | 시도 결과 산출물(성공의 구조적 자식) |
| `reused-credential` | credential → (host\|service) | ✘ | 크리덴셜 재사용(cross-cutting) |
| `blocked-by` | (technique\|finding) → (node) | ✘ | 진행 차단 원인(cross-cutting) |

> `succeeded`/`failed`를 **별도 relation으로 두지 않는다.** 성공/실패는 `attempted` 엣지의
> `status` 값(`succeeded`\|`attempt-failed`)으로 표현한다. 성공 시 산출물이 있으면 별도
> `yielded` 엣지로 연결한다. 이렇게 하면 "같은 finding에 여러 번 시도"가 상태 전이로 자연스럽게 기록된다.

### 1.5 상태 열거형과 색 매핑

`NodeStatus` / `EdgeStatus` 공통 어휘:

| status | 색(기본 팔레트) | 의미 |
|---|---|---|
| `untried` | 회색 `#8b8b93` | 발견됐지만 아직 시도 안 함 → "안 해본 시도" |
| `in-progress` | 앰버 `#f5a524` | 진행 중 |
| `attempt-failed` | 레드 `#e5484d` | 시도했으나 실패 → "막힌 지점" |
| `succeeded` | 그린 `#30a46c` | 성공 |
| `blocked` | 퍼플 `#8e4ec6` | 외부 요인/의존성으로 막힘(`blocked-by` 있음) |
| `not-applicable` | 흐린 회색 `#5a5a60` | 해당 없음으로 정리됨 |

- 노드 status는 그 노드로 향하는/그 노드가 대표하는 시도의 종합 상태를 뜻한다.
  (예: service 노드 아래 모든 technique이 실패면 service는 시각적으로 "막힘"을 부각)
- 색은 status가 결정, 아이콘/모양은 type이 결정한다.
- **color-by-type 토글**: 참고 이미지처럼 타입별 색을 쓰고 싶을 때. type→색 팔레트는
  `host`/`service`/`finding`/`technique`/`credential` 5색 고정.

### 1.6 파생 규칙 (`structural`)

- `structural = (relation ∈ {discovered, enumerated, attempted, yielded})`
- `reused-credential`, `blocked-by`는 항상 비구조적(cross-cutting) → 트리 골격에 쓰지 않고
  항상 `↗ 참조`로만 표현. 이것이 "크리덴셜 재사용을 복제 없이 참조로" 요구사항을 만족시킨다.

### 1.7 무결성 규칙 (백엔드 검증)

- 모든 node/edge는 동일 `projectId` 안에서만 연결. 교차-프로젝트 엣지 금지.
- `source`/`target`은 존재하는 노드여야 함(외래키).
- 각 relation은 정의된 타입 쌍만 허용(위 표). 위반 시 422.
- root 노드는 삭제 불가(2.1). 노드 삭제 시 관련 엣지 cascade, 단 삭제 감사 로그 남김.

---

## 2. Root 선택 & Canonical 판정 알고리즘

### 2.1 Root 선택

프로젝트 = 하나의 대상이므로 root는 자동·고정이다.

```
resolveRoot(project):
    if project.rootNodeId != null and nodeExists(project.rootNodeId):
        return project.rootNodeId
    # 최초 설정: 가장 이른 host 노드, 없으면 가장 이른 노드
    hosts = nodes(project).filter(type == "host").sortBy(createdAt, id)
    root = hosts.first() ?? nodes(project).sortBy(createdAt, id).first()
    project.rootNodeId = root.id      # 고정(persist)
    return root.id
```

- 최초 nmap 가져오기 시 host 노드가 생성되며 이때 root로 확정된다.
- 이후 root는 변하지 않는다(수동 재지정은 관리 기능으로만, 감사 로그 필수).

### 2.2 Canonical parent 결정 (트리 골격 계산)

다중 부모 노드가 있을 때 "먼저 발견/시도된 경로"가 canonical이다. **결정론적**이어야 리포트가 재현된다.

각 노드의 canonical parent = 그 노드로 들어오는 **structural 엣지 중 `createdAt` 최소값**,
동률이면 엣지 `id`(ULID) 사전순 최소.

```
computeCanonicalParents(project):
    parentOf = {}                 # nodeId -> chosen structural edge
    for n in nodes(project):
        incoming = edges(project).filter(e ->
            e.target == n.id and e.structural == true)
        if incoming.isEmpty():
            parentOf[n.id] = null            # root 또는 detached
        else:
            parentOf[n.id] = incoming
                .sortBy(e -> (e.createdAt, e.id))   # 오름차순
                .first()
    return parentOf
```

- 이 선택으로 각 노드는 structural 부모를 최대 1개 가진다 → 골격은 트리(=forest).
- root는 `parentOf == null`이 되도록 보장(root에는 structural incoming 없음이 정상).

### 2.3 트리 전개 + 참조/순환 표시

canonical parent 골격을 root에서 DFS로 펼치고, **골격에 쓰이지 않은 나머지 엣지**는
소스 노드 아래에 `↗ 참조`(또는 순환이면 `↩ 순환 참조`) 리프로 부착한다.

```
buildTree(project):
    root = resolveRoot(project)
    parentOf = computeCanonicalParents(project)
    childrenOf = invert(parentOf)          # canonicalEdge 기준 자식 목록

    placed = {}          # nodeId -> 트리 상 canonical 경로(path)
    order  = []          # 방문 순서(리포트 번호용)

    def walk(nodeId, path):
        placed[nodeId] = path
        order.push(nodeId)
        tnode = TreeNode(nodeId, path)
        # 1) 구조적 자식(canonical): createdAt,id 오름차순
        kids = childrenOf[nodeId].sortBy(e -> (e.createdAt, e.id))
        for e in kids:
            tnode.children.push(walk(e.target, path + [nextIndex]))
        # 2) 비-canonical 엣지 = 참조 리프
        refs = edges(project).filter(e ->
            e.source == nodeId and e != parentOf.get(e.target))
        for e in refs.sortBy(e -> (e.createdAt, e.id)):
            if isAncestor(e.target, nodeId, placed):     # 조상으로 되돌아감
                tnode.children.push(RefLeaf(kind="cycle", edge=e, target=e.target))
            else:
                tnode.children.push(RefLeaf(kind="ref",   edge=e, target=e.target))
        return tnode

    tree = walk(root, [1])

    # detached: canonical 체인이 root에 닿지 않는 노드 → root 아래 "미연결" 섹션
    detached = nodes(project).filter(n -> n.id not in placed and n.id != root)
    if detached.nonEmpty():
        tree.children.push(DetachedSection(detached.sortBy(createdAt,id)))
    return tree
```

핵심 성질:

- **복제 없음**: 각 노드는 정확히 한 번 canonical 위치에 놓인다(`placed`).
- **참조**: canonical이 아닌 모든 연결(특히 `reused-credential`, `blocked-by`, 다중 부모의 나머지)은
  `↗ 참조` 리프로만 표현되고 canonical 노드를 가리킨다.
- **순환**: 참조 대상이 현재 경로의 조상이면 `↩ 순환 참조`로 표기하고 더 내려가지 않는다.
- **결정론**: 정렬 키가 `(createdAt, id)`로 고정 → 같은 데이터는 항상 같은 트리·같은 번호.

---

## 3. 뷰 명세

### 3.1 Graph 뷰 (force-directed, 탐색용)

**목적**: 전체 연결과 cross-cutting(크리덴셜 재사용 등)을 시각적으로 드러내 "막힘/미시도"를 즉시 파악.

레이아웃
- 물리 시뮬레이션(force-directed). 권장 라이브러리: `d3-force`(경량, 커스텀 용이).
  대안 `@react-sigma`/`react-force-graph`. 기존 스택이 순수 React/Vite이므로 D3-force + SVG/Canvas 조합 권장.
- 노드 수 200 초과 시 Canvas 렌더 + 뷰포트 컬링. 그 이하 SVG로 충분.
- 힘 구성: `forceLink`(거리는 relation별 가변), `forceManyBody`(반발), `forceCollide`(겹침 방지),
  `forceCenter`. `pinned`/`position` 노드는 시뮬레이션에서 고정.

비주얼("고급스러운 UI" 톤)
- 다크 캔버스, 은은한 그리드/비네트 배경. 노드는 부드러운 글로우, 상태색 채움 + 미세한 외곽선.
- 노드 크기 = 중요도(예: 자식 수 또는 성공 산출물 수)로 가변.
- 아이콘: type별 라인 아이콘(host=서버, service=플러그, finding=돋보기, technique=번개, credential=열쇠).
- 엣지: 상태색. `structural`은 실선, cross-cutting(`reused-credential`/`blocked-by`)은 점선 + 곡선.
  방향 화살표(작게). 성공 경로는 약한 애니메이션 흐름(옵션, 접근성 위해 off 가능).
- 색 범례 고정 패널. **status/type 색 토글** 스위치.

인터랙션
- 드래그: 노드 이동(놓으면 `pinned=false`면 재정착, 더블클릭으로 pin/unpin).
- 호버: 툴팁(label, status, 최근 updatedAt, notes 요약). 연결 엣지 하이라이트, 나머지 디밍.
- 클릭: 우측 상세 패널(전체 meta, notes 편집, status 변경, sourceRef 바로가기).
- 필터 바: type/status/tag별 표시 토글, 텍스트 검색(라벨/노트). "미시도만", "막힌 것만" 프리셋.
- 포커스 모드: 특정 노드 선택 시 N-hop 이웃만 표시.
- 미니맵(노드 다수 시).
- "이 노드를 트리에서 보기" 버튼 → Tree 뷰로 전환하며 해당 canonical 위치로 스크롤/펼침.

빈/로딩 상태
- 프로젝트에 노드 없음 → "nmap 결과를 가져와 시작하세요" CTA(기존 nmap import로 딥링크).

### 3.2 Reference Tree 뷰 (정리·리포트용)

**목적**: root에서 펼친 절차적 트리. 리포트 목차와 1:1.

구조
- 들여쓰기 트리. 각 행: `[아이콘] label  [status 배지]  [번호 §1.2.3]`.
- 번호는 `buildTree`의 `order`/`path` 기반(리포트 섹션 번호와 동일).
- `↗ 참조` 리프: 흐린 스타일 + 화살표 아이콘 + "→ §canonical번호 label".
- `↩ 순환 참조` 리프: 순환 아이콘 + "↩ §조상번호 label".
- "미연결" 섹션: root에 닿지 않은 노드 모음(정리 유도).

확장/축소 동작
- 각 노드 좌측 토글(▶/▼). 기본: root부터 2단계 펼침, 이하 접힘.
- 단축: "성공 경로만 펼치기", "실패/미시도만 펼치기", "전체 펼침/접힘".
- 접힌 노드에 하위 상태 요약 배지(예: `S2 F3 U5` = 성공2 / 실패3 / 미시도5).

`↗ 참조` 클릭 인터랙션 (요구된 핵심)
1. 클릭 시 canonical 노드까지의 경로를 모두 펼친다.
2. canonical 행으로 스무스 스크롤 + 1.5초 하이라이트 펄스.
3. "돌아가기" 플로팅 버튼 제공(참조를 눌렀던 위치로 복귀) → 왕복 탐색 지원.
4. 키보드: `Enter`=점프, `Esc`/`Backspace`=복귀.

편집
- 인라인 status 변경, notes 편집(우측 패널 공유). 구조 변경(엣지 추가/삭제)은 그래프 뷰 또는 상세 패널에서.
- 드래그로 순서 변경은 금지(순서는 `createdAt` 결정론 유지). 대신 "canonical 재지정"은 명시적 액션(3.3).

### 3.3 canonical 수동 재지정(선택 기능, 감사 필요)

- 기본은 timestamp 규칙 자동. 사용자가 특정 노드의 canonical parent를 바꾸고 싶으면
  `pinnedCanonicalEdgeId`를 노드에 설정 → `computeCanonicalParents`에서 이 값이 있으면 우선.
- 리포트 재현성을 위해 이 override는 프로젝트에 영구 저장되고 감사 로그를 남긴다.

---

## 4. 스코핑 & 저장 (다중 프로젝트)

### 4.1 스코핑

- 그래프는 **프로젝트 단위로 완전히 격리**된다. 모든 조회/변경은 `projectId` 필수.
- 프로젝트는 기존 `core` 모듈의 Project와 1:1로 매핑(또는 Target 단위로 세분 가능 — 열린 질문 Q1).
- 교차-프로젝트 참조 없음(엣지 무결성 규칙 1.7).

### 4.2 저장 형태

기존 아키텍처(SQLite 단일 사용자)에 맞춰 **DB 저장을 1차**로 한다.

테이블(신규, `graph_` 접두):
```
graph_node(
  id TEXT PK, project_id TEXT FK, type TEXT, label TEXT, status TEXT,
  created_at TEXT, updated_at TEXT, source_ref JSON, notes TEXT,
  tags JSON, pinned INT, position JSON, meta JSON,
  pinned_canonical_edge_id TEXT NULL
)
graph_edge(
  id TEXT PK, project_id TEXT FK, source TEXT FK, target TEXT FK,
  relation TEXT, status TEXT, created_at TEXT, updated_at TEXT,
  label TEXT, meta JSON
)
graph_project_meta(
  project_id TEXT PK, root_node_id TEXT, schema_version INT,
  layout JSON, updated_at TEXT
)
```
인덱스: `(project_id)`, `graph_edge(project_id, target)`(canonical 계산), `graph_edge(project_id, source)`.

`structural`은 저장 컬럼이 아니라 `relation`에서 파생(뷰/서비스 레이어에서 계산)해 불일치를 원천 차단.

### 4.3 Export/Import (이식성)

- 프로젝트 그래프를 단일 JSON으로 export/import:
  ```json
  {
    "schemaVersion": 1,
    "project": { "id": "...", "rootNodeId": "...", "layout": {} },
    "nodes": [ ... ],
    "edges": [ ... ]
  }
  ```
- import 시 무결성 규칙(1.7) 재검증. 비밀은 `secretRef`만 이동(평문 미포함).
- 백업/버전관리: export JSON은 사람이 diff 가능하도록 노드/엣지를 `id` 정렬해 직렬화.

### 4.4 다중 프로젝트 UI

- 상단 프로젝트 스위처(기존 Project 목록 재사용). 전환 시 해당 그래프만 로드.
- 프로젝트별 요약 카드(노드/엣지 수, 성공 경로 수, 막힌 노드 수, 미시도 수) — 대시보드용.

---

## 5. 트리 → 리포트 아웃라인 Export

### 5.1 매핑 규칙

트리를 OSCP 리포트의 host별 절차적 서술 구조로 변환한다.

| 트리 요소 | 리포트 산출 |
|---|---|
| root(host) | 최상위 섹션 "Host: `<ip>` (`<hostname>`)" |
| service | 하위 섹션 "Service Enumeration — `<port>/<proto> <name>`" |
| finding | 하위 항목 "Finding — `<label>`" (severity/CVE 표기) |
| technique(성공) | "Exploitation — `<label>`" (명령/도구/결과) |
| technique(실패) | "Attempted (Unsuccessful) — `<label>`" (실패 서술; 정직성) |
| credential | "Credentials Obtained/Used" (비밀 마스킹) |
| `↗ 참조` | 본문 내 상호참조 "(§x.y 참조)" — 재서술하지 않음 |
| `↩ 순환 참조` | 각주형 상호참조로 축약 |
| detached | "Misc / Unlinked Observations" 부록 |

- 섹션 번호 = `buildTree`의 `path`. 결정론적이라 리포트 재생성 시 안정.
- 각 노드의 `notes`(Markdown)가 본문 서술 원천. `evidenceRefs`는 그림/부록 링크로 변환.
- 성공 경로(root→…→succeeded)를 우선 배치하도록 "성공 우선" 정렬 옵션 제공(단, 기본은 트리 순서 유지).

### 5.2 출력 형식

세 가지 export 타깃:

1. **Markdown 아웃라인** (헤딩 레벨 = 깊이):
   ```
   # Host: 10.10.10.5 (dc01)
   ## 445/tcp smb — enumerated
   ### Finding — MS17-010 (critical, CVE-2017-0144)
   #### Exploitation — eternalblue (succeeded)
   > <notes 본문>
   #### Attempted (Unsuccessful) — smb null session
   (see §2.1 for reused credential)
   ```
2. **구조화 JSON 아웃라인** (기존 `reports` 모듈이 소비):
   ```json
   { "section": "1", "title": "Host: 10.10.10.5", "status": "succeeded",
     "sourceRef": {...}, "body": "…md…",
     "crossRefs": [{"kind":"ref","to":"2.1"}],
     "children": [ … ] }
   ```
3. **리포트 목차(ToC) 프리뷰**: 번호·제목·status 배지만. UI에서 리포트 생성 전 확인용.

- export는 **읽기 전용 변환**이며 그래프를 수정하지 않는다.
- 기존 `reports` 모듈 원칙("AI 분석/결론 생성 금지")을 준수: 변환은 사용자가 쓴 notes·status를
  구조로 옮길 뿐 판정/결론을 생성하지 않는다.

---

## 6. API 초안 (기존 `/api` 규약에 맞춤)

```
GET    /api/projects/{pid}/graph                # 전체 nodes+edges+meta
POST   /api/projects/{pid}/graph/nodes          # 노드 생성
PATCH  /api/graph/nodes/{id}                     # status/notes/tags/position 등
DELETE /api/graph/nodes/{id}                     # (root 불가) 감사 로그
POST   /api/projects/{pid}/graph/edges           # 엣지 생성(타입쌍 검증)
PATCH  /api/graph/edges/{id}
DELETE /api/graph/edges/{id}
GET    /api/projects/{pid}/graph/tree            # buildTree 결과(참조/순환 포함)
POST   /api/projects/{pid}/graph/root            # 수동 재지정(감사)
GET    /api/projects/{pid}/graph/export          # JSON export
POST   /api/projects/{pid}/graph/import          # JSON import(검증)
GET    /api/projects/{pid}/graph/report-outline?format=md|json|toc
POST   /api/projects/{pid}/graph/sync            # 기존 도메인→그래프 투영 동기화(6.1)
```

### 6.1 기존 도메인 → 그래프 투영(sync)

- nmap import/서비스 발견 시 자동으로 host/service 노드와 `discovered` 엣지를 생성(idempotent, `sourceRef`로 중복 방지).
- Runbook/Execution 진행이 technique 노드/`attempted` 엣지로 반영되도록 훅 제공(선택).
- 투영은 **덮어쓰지 않고 병합**: 사용자가 그래프에서 수정한 label/notes/status는 보존, sourceRef 원천 필드만 갱신.

---

## 7. 비기능 요구사항

- 성능: 노드 500/엣지 1500까지 60fps 목표(Canvas 폴백). 트리·canonical 계산은 O(N log N).
- 접근성: 색만으로 상태 구분하지 않도록 status 배지 텍스트/아이콘 병행. 애니메이션 off 옵션.
- 결정론: 동일 데이터 → 동일 트리·동일 리포트 번호(정렬 키 고정).
- 로컬 전용/보안: 기존 경계 준수(127.0.0.1 바인딩, 비밀 마스킹, credential opt-in).
- 실행/자동판정 금지: 그래프는 사용자가 입력·표시한 상태만 저장하며 취약 여부·공격경로를 자동 판정하지 않는다(제품 원칙 일치).

---

## 8. 구현 단계(제안)

1. **M1 스키마·저장**: 테이블, 무결성 검증, CRUD API, export/import.
2. **M2 트리 엔진**: canonical 계산 + buildTree + tree API(단위 테스트로 결정론 고정).
3. **M3 Tree 뷰**: 확장/축소, `↗`/`↩` 참조 점프·복귀.
4. **M4 Graph 뷰**: d3-force, 상태색/타입아이콘, 필터·상세 패널, status 토글.
5. **M5 리포트 export**: md/json/toc, `reports` 모듈 연동.
6. **M6 sync 훅**: nmap/서비스 자동 투영, 대시보드 요약 카드.

---

## 9. 열린 질문 (사용자 확인 필요)

- **Q1. 프로젝트 = Project vs Target 단위?**
  기존 모델은 Project 1—N Target이다. "프로젝트 = 하나의 대상 호스트"라면 그래프 스코프를
  Project가 아니라 **Target** 단위로 잡아야 할 수 있다. 다중 호스트 랩에서 어떻게 다룰지 확정 필요.
  (제안 기본값: 그래프 스코프 = Target. root = 해당 Target의 최초 nmap host 노드.)

- **Q2. pivot/다중 호스트 표현.**
  랩이 여러 호스트로 확장(내부망 pivot)될 때, 새 호스트를 같은 그래프에 second host 노드로
  넣을지, 별도 그래프로 분리할지? cross-host 이동은 `yielded`(성공 산출물로서 새 host) vs
  새 relation `pivoted-to`가 필요할지.

- **Q3. canonical override 허용 범위.**
  3.3의 수동 재지정을 넣을지, 아니면 timestamp 규칙만으로 고정(단순·재현 우선)할지.

- **Q4. Execution/Runbook 자동 투영 강도.**
  기존 실행/런북 진행을 technique 노드로 자동 생성할지(편리하지만 노이즈), 수동 승격만 할지.

- **Q5. finding "severity"의 성격.**
  사용자 표기용 라벨로만 둘지(제품 원칙: 자동 판정 금지), CVSS류 계산은 배제 확정인지.

- **Q6. 상태 어휘 확정.**
  1.5의 `blocked`를 별도 status로 둘지, `blocked-by` 엣지 존재로만 표현하고 status는
  `attempt-failed`로 통일할지(어휘 최소화).

- **Q7. 리포트 정렬 정책.**
  기본을 "트리 순서(발견순)"로 둘지, "성공 경로 우선"으로 둘지. OSCP 리포트 관례에 맞춤 필요.

- **Q8. Graph 뷰 렌더러 선택.**
  순수 d3-force 자체 구현 vs `react-force-graph` 도입. 후자는 빠르지만 의존성 추가.
  프로젝트의 의존성 최소화 방침과 조율 필요.
