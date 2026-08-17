# 명세서: 진행상황 그래프 트래커 (Progress Graph Tracker)

- 상태: v1 — 모든 설계 결정 종결(§9), 구현 착수 가능
- 대상 스택: 기존 OSCP Workspace (FastAPI + SQLite 백엔드, React/Vite + TypeScript 프론트)
- 배치: `backend/app/modules/graph`, `frontend/src/features/graph`
- 범위: 허가된 랩/연습 환경의 **개인 진행상황 트래킹** 전용. 실제 시험 세션 사용을 목표로 하지 않는다.

---

## 0. 한 줄 요약

하나의 프로젝트(여러 대상 호스트 포함)에 대해 정찰→열거→시도→결과의 흐름을 **단일 그래프**
`(nodes, edges)`로 저장하고, 같은 데이터를 **역할이 분리된 3개 뷰**로 렌더링한다.

- **Graph 뷰** (Pixi.js + d3-force): 탐색용. Obsidian급 유기적 네트워크로 "어디서 막혔나 / 무엇을 안 해봤나"를 드러냄.
- **Outline 뷰** (React DOM + CSS + Motion): 작업·정리용. root(합성 project-root)에서 펼친 아웃라인이며, 다중 부모/순환은
  복제하지 않고 `↗ 참조` / `↩ 순환 참조`로 canonical 노드를 가리킨다. IDE/Linear급 micro-interaction 포함.
- **Attack Path 뷰** (SVG): 결과·설명용. 성공한 침투 흐름만 추린 선형 시각화.

세 뷰는 **같은 데이터**를 공유하고 렌더러/레이아웃만 다르다. Outline 구조는 종료 후 리포트 목차로 그대로 변환된다.

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
| `type` | enum `NodeType` | ✔ | `project-root` \| `operator` \| `host` \| `service` \| `finding` \| `technique` \| `credential` |
| `label` | string | ✔ | 화면 표시명 (예: `445/tcp smb`, `MS17-010`) |
| `status` | enum `NodeStatus` | ✔ | 아래 1.5. 색 인코딩의 근거 |
| `createdAt` | ISO-8601 datetime | ✔ | **canonical 판정의 기준값**. 최초 발견/시도 시각 |
| `updatedAt` | ISO-8601 datetime | ✔ | 마지막 변경 시각 |
| `sourceRef` | object \| null | – | 기존 도메인 역참조 `{ module, kind, id }` (예: `{module:"scans", kind:"service", id:42}`) |
| `notes` | string (Markdown) | – | 자유 메모. 리포트 서술 원천 |
| `tags` | string[] | – | 자유 태그 (`quick-win`, `rabbit-hole` 등) |
| `pinned` | boolean | – | 레이아웃 고정 여부 (그래프 뷰) |
| `position` | `{x,y}` \| null | – | 수동 배치 좌표 캐시. null이면 시뮬레이션이 결정 |
| `objective` | boolean | – | 이 노드가 **목표/마일스톤**인지. 기본 false. OSCP의 `local.txt`/`proof.txt` 캡처, DA 획득 등 |
| `objectiveKind` | enum \| null | – | `foothold`\|`privesc`\|`flag`\|`domain-admin`\|`custom`. `objective=true`일 때만 의미 |
| `provenance` | object \| null | – | 이 노드를 생성/발견한 근거: `{ techniqueRef?, executionRef?, mitreId?, tool? }`. NodeZero `found_by_module` 대응(§10) |
| `layer` | number \| null | – | 타임라인 timestep(같은 시각 노드 그룹 인덱스). null이면 `createdAt`에서 파생. timeline 렌더용 |
| `hidden` | boolean | – | 사용자가 숨긴 클러터. 기본 false. Graph/Outline/Attack Path에서 제외되나 노드는 남아 sync가 되살리지 않음 |
| `meta` | object | – | 타입별 필드(1.3) |

> **provenance vs sourceRef vs yielded** — `sourceRef`는 기존 도메인 엔티티 역참조, `yielded` 엣지는 구조적
> 산출 관계, `provenance`는 "이 노드를 만든 **구체적 실행/기법 + MITRE**"의 스탬프다(리포트의 "어떻게 획득했는가"
> 서술 원천). yielded 엣지로 이미 표현되는 경우 `provenance.techniqueRef`는 그 엣지 source와 일치할 수 있다.

> **layer/timeline** — 우리는 `createdAt`을 이미 보유하므로 timeline 렌더는 사실상 무료다. `layer`는 "같은 시각에
> 발견/시도된 노드들"을 하나의 timestep으로 묶는 선택적 파생/명시 필드(NodeZero `subflow_nodes` timestep 모델 대응).
> 별도 timeline 뷰는 발전 후보이며, 데이터 필드는 지금 확보해 둔다.

> **`project-root`** 은 시스템이 프로젝트당 1개 자동 생성하는 합성 노드다(사용자 생성 불가, 삭제 불가).
> 다중 Target(2.1)을 담는 트리·리포트의 최상위 앵커이며 `meta`는 비어 있거나 프로젝트 요약만 담는다.

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
| `operates` | project-root → operator | ✔ | 프로젝트의 로컬 Kali/Operator 작업점 |
| `runs` | operator → technique | ✔ | 로컬 Operator에서 리스너·도구 실행 |
| `captures-from` | technique → host | ✘ | 로컬 리스너가 대상에서 인증 시도를 수신 |
| `scans` | technique → host | ✘ | AutoRecon 실행이 포함한 대상 참조 |
| `discovered` | host → service | ✔ | 스캔이 서비스를 발견 |
| `enumerated` | (service\|host) → (finding\|credential) | ✔ | 열거로 finding/크리덴셜 도출(host-level 관찰·설정파일 크리덴셜 포함) |
| `attempted` | (finding\|service\|host) → technique | ✔ | 기법 시도(finding 대상 익스플로잇, 또는 서비스/호스트에 직접 실행) |
| `yielded` | technique → (credential\|host\|service\|finding) | ✔ | 시도 결과 산출물(성공의 구조적 자식) |
| `pivoted-to` | host → host | ✔ | 호스트 간 Lateral Access. 관계명은 호환성을 위해 유지하며 실제 network pivot 여부는 meta/evidence로 구분 |
| `reused-credential` | credential → (host\|service) | ✘ | 크리덴셜 재사용(cross-cutting) |
| `blocked-by` | (technique\|finding) → (node) | ✘ | 진행 차단 원인(cross-cutting) |

> **`pivoted-to` vs `reused-credential`** — `pivoted-to`는 host→host의 구조적 Lateral Access,
> `reused-credential`은 어떤 Credential이 목적 host/service를 열었는지 보여주는 cross-cutting 참조다.
> Credential이 source host에서 발견됐다는 사실만으로 트래픽이 그 host를 경유했다고 주장하지 않는다. 실제 network
> Pivot은 Tunnel/Proxy Evidence가 있을 때만 그렇게 표시한다.

> `succeeded`/`failed`를 **별도 relation으로 두지 않는다.** 성공/실패는 `attempted` 엣지의
> `status` 값(`succeeded`\|`attempt-failed`)으로 표현한다. 성공 시 산출물이 있으면 별도
> `yielded` 엣지로 연결한다. 이렇게 하면 "같은 finding에 여러 번 시도"가 상태 전이로 자연스럽게 기록된다.

### 1.5 상태 열거형과 색 매핑

`NodeStatus` / `EdgeStatus` 공통 어휘:

| status | 색(기본 팔레트) | 의미 |
|---|---|---|
| `untried` | 회색 `#8b8b93` | 발견됐지만 아직 시도 안 함 → "안 해본 시도" |
| `in-progress` | 앰버 `#f5a524` | 진행 중 |
| `attempt-failed` | 레드 `#e5484d` | 내가 시도했고 실패함 → "막힌 지점" |
| `succeeded` | 그린 `#30a46c` | 성공 |
| `blocked` | 퍼플 `#8e4ec6` | 외부 요인/선행 의존성 때문에 아직 시도조차 못 함(`blocked-by` 있음) |
| `not-applicable` | 흐린 회색 `#5a5a60` | 해당 없음으로 정리됨 |

- 노드 status는 그 노드로 향하는/그 노드가 대표하는 시도의 종합 상태를 뜻한다.
  (예: service 노드 아래 모든 technique이 실패면 service는 시각적으로 "막힘"을 부각)
- `attempt-failed`와 `blocked`는 별도 status로 유지한다(Q6). 전자는 "내가 해봤는데 안 됨", 후자는 "선행조건 때문에
  아직 못 함"으로 의미가 다르며, 트래커의 1차 목적("막힌 지점 vs 안 해본 시도" 구분)상 합치면 안 된다.
- 색은 status가 결정, 아이콘/모양은 type이 결정한다.
- **color-by-type 토글**: 참고 이미지처럼 타입별 색을 쓰고 싶을 때. type→색 팔레트는
  `host`/`service`/`finding`/`technique`/`credential` 5색 고정.

### 1.6 파생 규칙 (`structural`)

- `structural = (relation ∈ {operates, runs, discovered, enumerated, attempted, yielded, pivoted-to})`
- `scans`, `captures-from`, `reused-credential`, `blocked-by`는 항상 비구조적(cross-cutting) → 트리 골격에 쓰지 않고
  항상 `↗ 참조`로만 표현. 이것이 "크리덴셜 재사용을 복제 없이 참조로" 요구사항을 만족시킨다.

### 1.7 무결성 규칙 (백엔드 검증)

- 모든 node/edge는 동일 `projectId` 안에서만 연결. 교차-프로젝트 엣지 금지.
- `source`/`target`은 존재하는 노드여야 함(외래키).
- 각 relation은 정의된 타입 쌍만 허용(위 표). 위반 시 422.
- root 노드는 삭제 불가(2.1). 노드 삭제 시 관련 엣지 cascade, 단 삭제 감사 로그 남김.

---

## 2. Root 선택 & Canonical 판정 알고리즘

### 2.1 Root 선택 (프로젝트 스코프 · 다중 Target)

**결정(Q1/Q2):** 그래프 스코프는 **Project** 단위다. 하나의 Project 그래프 안에 여러 Target(호스트)이
공존하며 서로 연결(`pivoted-to`, 호스트 간 `reused-credential`)될 수 있다. 따라서 root는 단일 호스트가 아니라
**프로젝트당 1개의 합성 `project-root` 노드**로 고정한다.

```
resolveRoot(project):
    if project.rootNodeId != null and nodeExists(project.rootNodeId):
        return project.rootNodeId
    # 합성 루트 자동 생성(프로젝트당 1개, idempotent)
    root = ensureNode(project, type="project-root",
                      label=project.name, status="in-progress")
    project.rootNodeId = root.id            # 고정(persist)
    return root.id

# 각 Target의 최초 host 노드는 project-root 아래 최상위 섹션으로 붙는다.
attachHost(project, hostNode):
    if not exists(edge where source==rootOf(project) and target==hostNode and structural):
        createEdge(source=rootOf(project), target=hostNode,
                   relation="discovered", status=hostNode.status,
                   createdAt=hostNode.createdAt)   # host의 시각을 승계 → canonical 순서 보존
```

- project-root는 사용자가 만들거나 지울 수 없다. 트리·리포트의 최상위(H1 위의 프로젝트 제목)이다.
- **Graph 뷰의 적응형 루트(결정 B):** 보이는 host가 **1대뿐이면 project-root를 숨기고 그 host를 시각적 루트**(중심
  고정 앵커)로 둔다. host가 **2대 이상이면 project-root가 중심 앵커로 등장**하고 host들이 그 아래로 뻗는다. 즉 단일 박스
  랩에서는 "nmap 호스트 = 루트"라는 사용자 직관대로 보이고, pivot으로 머신이 늘면 자연스럽게 project-root가 상위
  컨테이너로 드러난다. 루트(앵커)는 캔버스 중심에 고정하되 **빈 공간 드래그로 화면 전체를 패닝**할 수 있다.
  (Outline/리포트에서는 단일 host일 때 project-root 행을 생략하고 host를 최상위로 올린다.)
- 각 host는 `project-root → host` 의 `discovered` 엣지로 부착되며, 이 엣지의 `createdAt`은 host의 최초 발견 시각을
  승계해 **다중 호스트 사이의 canonical 정렬(발견순)**을 보존한다.
- 내부망으로 확장된 호스트는 project-root가 아니라 자신을 발견하게 한 pivot 호스트 아래에 `pivoted-to`로 중첩된다
  (즉 외부 진입점 호스트만 project-root 직속, 내부 호스트는 pivot 체인 아래).
- root(project-root) 자체는 변하지 않는다. host의 canonical 배치는 수동 재지정(2.3, Q3 허용) 가능.

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
        if n.pinnedCanonicalEdgeId != null:      # 수동 override(3.5, Q3)
            parentOf[n.id] = edge(n.pinnedCanonicalEdgeId)
        elif incoming.isEmpty():
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

## 3. 뷰 명세 — 3-뷰 아키텍처

**결정(Q8):** 하나의 데이터 위에 **역할이 명확히 분리된 3개 뷰**를 둔다. 상단 세그먼트 탭으로 전환한다.

```
[ Graph ]      [ Outline ]        [ Attack Path ]
 탐색용          작업·정리용         결과·설명용
 Pixi.js        React DOM          Pixi.js / SVG
```

| 뷰 | 역할 | 렌더러 | 성격 |
|---|---|---|---|
| **Graph** | 탐색 — 전체 연결·cross-cutting을 유기적으로 | **Pixi.js(WebGL) + d3-force + Graphology** | 공간적, 자유 배치 |
| **Outline** | 작업·정리 — 정보 밀도 높은 인터랙티브 아웃라인 | **React DOM + CSS + Motion** | 문서적, 계층 |
| **Attack Path** | 결과 설명 — 성공한 침투 흐름의 선형 시각화 | **SVG(+dagre 레이아웃)** | 정적·계층적, 방향성 |

세 뷰는 **동일한 `(nodes, edges)`**를 공유하고 렌더러/레이아웃만 다르다. 아래 3.4의 컴포넌트 경계로 렌더러를
교체·추가해도 데이터·상태 계층은 불변이어야 한다.

### 3.0 렌더러 스택 결정 (구현 확정)

- **Graph = Pixi.js(WebGL)** — Obsidian급 유기적 네트워크. SVG는 수백 노드에서 무너지고 글로우/블룸 질감을 못 낸다.
- **물리/레이아웃 = d3-force** — 렌더러와 독립. 매 tick 좌표만 Pixi에 전달. **v1은 메인 스레드**, 대규모 시 Web Worker로 이관(과설계 방지 위해 v1엔 넣지 않음).
- **그래프 데이터/알고리즘 = Graphology** — 단, **단일 진실 소스가 아니다.** 원본은 우리 스키마(§1)이고 Graphology는
  렌더·알고리즘(이웃 조회, connected-components, centrality 기반 노드 크기)을 위한 **파생 인메모리 인덱스**로만 쓴다. 둘 다에 상태를 쓰면 동기화 버그가 난다.
- **React = UI shell 전용** — 컨트롤 패널·필터·Inspector(상세 패널)만. **캔버스 렌더 루프에 React state를 절대 넣지 않는다.**
  Pixi ↔ React는 ref 기반 imperative API + 이벤트 버스로 연결. 히트테스트(클릭/호버)는 Pixi sprite interaction으로 처리.

### 3.1 Graph 뷰 (Pixi.js, 탐색용)

**목적**: 전체 연결과 cross-cutting(크리덴셜 재사용, blocker 등)을 유기적으로 드러내 "막힘/미시도"를 즉시 파악.

레이아웃/물리
- d3-force: `forceLink`(거리 relation별 가변), `forceManyBody`(반발), `forceCollide`(겹침 방지), `forceCenter`.
  `pinned`/`position` 노드는 시뮬레이션에서 고정. 루트 앵커는 중심 고정 + 빈 공간 드래그로 패닝(적응형 루트는 §2.1 참조).

비주얼(Obsidian급 톤)
- 다크 캔버스, 은은한 비네트/그리드 배경. 노드는 부드러운 글로우 + 상태색 채움 + 미세 외곽선.
- 노드 크기 = 중요도(자식 수 또는 성공 산출물 수, Graphology centrality).
- type별 라인 아이콘(host=서버, service=플러그, finding=돋보기, technique=번개, credential=열쇠, project-root=원점).
- 엣지: 상태색. `structural`(pivoted-to 포함) 실선, cross-cutting(reused-credential/blocked-by) 점선+곡선.
  방향 화살표. 성공 경로는 약한 흐름 애니메이션(접근성 위해 off 가능).
- 색 범례 고정 패널 + **status/type 색 토글**.

인터랙션
- 드래그(이동/pin·unpin 더블클릭), 호버(툴팁 + 연결 하이라이트·나머지 디밍), 클릭(우측 Inspector 동기화).
- 필터 바(type/status/tag 토글, 텍스트 검색), 프리셋("미시도만"/"막힌 것만"), 포커스 모드(N-hop 이웃), 미니맵.
- "Outline에서 보기" 버튼 → Outline 뷰로 전환하며 canonical 위치로 스크롤/펼침.

### 3.2 Outline 뷰 (React DOM, 작업·정리용) — 렌더러 확정: React DOM

**렌더링 방식은 React DOM으로 확정한다. 이는 구현 편의성을 위한 선택이지 시각적 완성도를 낮추는 선택이 아니다.
기본 브라우저 트리 UI 수준은 허용하지 않는다.** 목표 수준은 Obsidian / Linear / 현대 IDE의 sidebar·outliner이며,
아래 micro-interaction을 포함한다. 시각적 완성도는 렌더러가 아니라 디자인/애니메이션 레이어(CSS + Motion)에서 올린다.

DOM을 쓰는 이유: 텍스트 선택, 컨텍스트 메뉴, inline edit, tooltip, focus 관리, drag/drop, 키보드 내비, 접근성이
전부 네이티브로 제공된다. 이를 Canvas로 구현하면 공수가 폭증하며 얻는 게 없다. 이 뷰는 시각화가 아니라 **문서**다.

목표 렌더 예시(계층 연결선·상태 배지 포함):
```
● 10.10.11.23
│
├─ ◉ 445 / SMB                    SUCCESS
│  ├─ ◇ Anonymous enumeration      ✓
│  └─ 🔑 svc_backup                ACQUIRED
│        └─ ↗ reused on 10.10.11.24
├─ ◉ 80 / HTTP                    ACTIVE
│  └─ ◇ Directory enumeration
│       ├─ /admin
│       └─ /uploads
└─ ◉ 22 / SSH                     BLOCKED
```

레이아웃
- `buildTree`(§2.3) 결과의 **중첩 들여쓰기**. d3-hierarchy/tidy-tree 같은 공간 배치가 아니라 CSS 들여쓰기 + 연결선.
  별도 레이아웃 라이브러리 불필요. 긴 트리는 react-window로 가상화(랩 규모면 v1엔 불필요).
- 각 행: `[계층 연결선] [type 아이콘] label [status 배지] [§번호]`.
- 왼쪽 계층 연결선(`│ ├─ └─`)은 CSS로 부드럽게 이어지게 그린다.

micro-interaction(요구사항 — 전부 포함)
- 노드 hover 시 배경 미세하게 밝아짐, 성공 경로는 subtle glow.
- `blocked`는 흐린 색 + blocker indicator(어떤 노드에 막혔는지 표시).
- expand/collapse 시 height/opacity 트랜지션. 노드 생성 시 scale/fade 애니메이션.
- 접힌 노드에 하위 상태 요약 배지(`S2 F3 U5` = 성공2/실패3/미시도5).
- 선택 노드는 우측 **Inspector와 실시간 동기화**.
- 키보드 `↑↓←→` 탐색(←접기/→펼치기), `/` 검색, **command palette**(노드 점프·status 변경 등).

`↗ reference` 내비게이션(핵심)
1. hover 시 대상 경로 **preview**(툴팁으로 canonical 위치·label 미리보기).
2. 클릭 시 대상까지의 경로를 자동 expand.
3. 대상 canonical 행으로 스무스 스크롤 + 이동하며 해당 노드에 **pulse**.
4. **Back 버튼**으로 참조를 눌렀던 원위치로 부드럽게 복귀(왕복 탐색). 키보드 `Enter`=점프, `Esc`/`Backspace`=복귀.
- `↩ 순환 참조`도 동일하게 조상 노드로 점프하되 더 내려가지 않음.

편집/정리
- 인라인 status 변경, notes 편집(Inspector 공유). 구조 변경(엣지 추가/삭제)은 Graph 뷰 또는 Inspector에서.
- 발견순(`createdAt`) 결정론을 지키기 위해 **자유 순서 재정렬은 금지**. 대신 canonical 재지정은 명시적 액션(3.5).
- "미연결" 섹션: root에 닿지 않은 노드 모음(정리 유도).

### 3.3 Attack Path 뷰 (Pixi.js/SVG, 결과·설명용)

**목적**: 성공한 침투 흐름을 공간적·선형으로 보여줌 — 리포트의 "공격 경로 요약" 그림. Outline이 전수 기록이라면
Attack Path는 그중 **root → … → 최종 권한**에 이르는 성공 체인만 추린 스토리보드다.

- 데이터: `project-root/host`에서 시작해 `succeeded` 상태의 `attempted`/`yielded`/`pivoted-to` 엣지를 따라가는
  경로(들)를 추출(§3.4의 selector). 여러 성공 경로가 있으면 병렬 레인으로 표시.
- 비주얼 예시(세로 방향 흐름):
```
[External] → [10.10.11.23] --HTTP--> [Web Exploit] → [www-data]
                                                        │ Credential
                                                        ▼
                                              [user] --PrivEsc--> [root]
```
- pivot(`pivoted-to`)은 호스트 경계를 넘는 화살표로 강조. 크리덴셜 재사용은 보조 점선으로.
- **요약 rollup(§3.4 selector):** 파생 Attack Path 상단에 `{ hosts, services, findings, techniques, credentials,
  steps, objectivesReached }` 카운트를 표시(NodeZero `AttackVector` 카운트/`total_score` 대응). 대시보드·리포트 헤더로 재사용.
- 상호작용은 최소(설명용): hover 시 단계 상세, 클릭 시 Inspector/Outline 해당 노드로 이동.
- **렌더러 = SVG 우선 확정(Q9).** Attack Path는 Graph와 달리 정적·계층적(선형 흐름)이라 물리 시뮬레이션이 없고,
  SVG가 더 적합하다(선명한 벡터, 손쉬운 라벨/화살표, 낮은 복잡도, PNG/PDF export 용이). Pixi 자원 공유 이점보다
  SVG의 단순함이 크다. dagre류 경량 계층 레이아웃으로 노드 배치, SVG로 렌더.

### 3.4 컴포넌트 경계 (렌더러 교체·추가 가능하게)

데이터·상태 계층을 렌더러로부터 분리한다. Attack Path 같은 뷰를 추가해도 아래 경계가 불변이어야 한다.

```
GraphStore (진실 소스: 우리 스키마, React 밖)
  ├─ selectors: buildTree(), successPaths(), neighbors(), filterBy()
  ├─ GraphologyIndex (파생 인덱스, 렌더·알고리즘용)
  └─ mutations: node/edge CRUD, status 전이, canonical override
        │
        ├─ <GraphView>       Pixi renderer  ← positions from d3-force
        ├─ <OutlineView>     React DOM      ← buildTree() 결과
        ├─ <AttackPathView>  Pixi/SVG       ← successPaths() 결과
        └─ <Inspector>       React DOM      ← 선택 노드(세 뷰 공유)
```

- 세 뷰는 `GraphStore`의 selector만 소비하고 서로를 모른다. 선택/포커스 상태만 공유(단일 selection store).
- `successPaths(project)` selector: root에서 `succeeded` 체인을 DFS로 추출 → Attack Path의 입력.
- `attackPathSummary(nodes, edges)` selector: 성공 체인에 포함된 노드를 타입별로 집계해
  `{ hosts, services, findings, techniques, credentials, steps, objectivesReached }` 반환 → Attack Path/리포트 헤더 rollup.

### 3.5 canonical 수동 재지정(Q3 — 허용 확정)

- 기본은 timestamp 규칙 자동(§2.2). 사용자가 특정 노드의 canonical parent를 바꾸려면
  노드에 `pinnedCanonicalEdgeId`를 설정 → `computeCanonicalParents`에서 이 값이 있으면 우선한다.
- 리포트 재현성을 위해 override는 프로젝트에 영구 저장되고 **감사 로그**를 남긴다.
- Outline/Graph 어디서든 "이 위치를 canonical로 지정" 액션으로 설정 가능.

### 3.6 Objective(목표) 표현 — OSCP-native

Pentera의 "critical asset"/root-cause 개념과 OSCP의 본질(플래그 캡처·권한 상승)을 흡수한다. 단, 목표는
**사용자가 손으로 지정**하며 시스템이 자동 추론하지 않는다(제품 원칙 준수).

- 데이터: 노드의 `objective`/`objectiveKind`(§1.2). 어떤 타입의 노드든 목표가 될 수 있다
  (예: host="root on 10.10.11.24", credential="Domain Admin", technique="proof.txt 캡처").
- **엔진 selector `pathsToObjectives(edges, objectiveIds)`**: `successPaths`(§3.3) 중 목표 노드에서 끝나거나
  목표를 지나는 체인만 추려 반환. Attack Path·Graph 하이라이트의 입력.
- 렌더링:
  - **Graph**: 목표 노드에 타겟(크로스헤어) 링 + 🎯 표식. "목표까지 경로" 토글 시 목표에 이르는 성공 체인을 강조.
    미달성 목표는 링만(흐리게), 달성 목표는 채워진 링.
  - **Attack Path**: 목표에서 끝나는 체인을 헤드라인으로. 목표 박스에 `OBJECTIVE` 배지.
  - **Outline**: 목표 행에 🎯 배지 + `objectiveKind` 라벨.
- 상태 결합: 목표의 달성 여부는 그 노드의 `status`(예: `succeeded`=달성, `untried`/`blocked`=미달성)로 읽는다.
  별도 "달성" 플래그를 두지 않아 단일 진실 소스를 유지한다.

---

## 4. 스코핑 & 저장 (다중 프로젝트)

### 4.1 스코핑

- **결정(Q1):** 그래프 스코프 = 기존 `core` 모듈의 **Project와 1:1**. 하나의 Project 그래프가 여러 Target(호스트)을 담는다.
- 모든 조회/변경은 `projectId` 필수. 교차-프로젝트 참조 없음(엣지 무결성 규칙 1.7).
- Project의 각 Target은 project-root 아래 host 노드로 편입되며(§2.1), Target 간 연결은 `pivoted-to`(골격) 또는
  `reused-credential`(cross-cutting)로 표현한다(Q2).

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
| project-root | 문서 제목 "Project: `<name>`" (H1 위 표지/개요) |
| host | 최상위 섹션(H1) "Host: `<ip>` (`<hostname>`)" |
| pivoted-to host | pivot 호스트 하위 섹션 "Lateral Movement → Host: `<ip>`" (중첩 유지) |
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
- **정렬 정책(Q7) — 뷰별로 다르다:**
  - **Outline(작업 화면) 기본 = 발견순(`createdAt`)**. 작업 기록의 흐름을 시간순으로 보존한다.
  - **Report(export) 기본 = 성공 경로 우선**. root→…→`succeeded` 체인을 앞에 배치하고, 실패/미시도는 뒤로 돌린다.
    최종 보고서의 목적은 "어떻게 뚫었는가"의 서술이라 성공 흐름을 앞세운다. 두 정렬 모두 tie-break는 `(createdAt, id)`로
    결정론을 유지한다(같은 데이터 → 같은 문서).

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
GET    /api/projects/{pid}/graph/tree            # Outline용 buildTree 결과(참조/순환 포함)
GET    /api/projects/{pid}/graph/attack-paths    # successPaths selector 결과(Attack Path 뷰)
PATCH  /api/graph/nodes/{id}/canonical           # pinnedCanonicalEdgeId 설정/해제(감사)
POST   /api/projects/{pid}/graph/root            # project-root 관리(감사)
GET    /api/projects/{pid}/graph/export          # JSON export
POST   /api/projects/{pid}/graph/import          # JSON import(검증)
GET    /api/projects/{pid}/graph/report-outline?format=md|json|toc
POST   /api/projects/{pid}/graph/sync            # 기존 도메인→그래프 투영 동기화(6.1)
GET    /api/projects/{pid}/graph/timeline        # append-only Graph Snapshot replay frames
```

### 6.1 기존 도메인 → 그래프 투영(sync)

- Targets/Services → host/service 노드 + `discovered`, Findings/Credentials → finding/credential 노드 +
  `enumerated`(서비스, 없으면 호스트에 부착). 크리덴셜 비밀은 절대 복사하지 않고 `secretHint`만.
- **Execution은 자동으로 technique 노드로 투영한다(Q4 — 재결정).** `attempted`(서비스/호스트→technique)로 부착하며
  provenance에 `executionRef`+MITRE를 스탬프한다. **단 성공 여부는 자동 판정하지 않는다**(제품 원칙): 완료된 명령을
  `succeeded`로 찍지 않고 중립(`in-progress`)으로 두며 기술적 실패/중단만 `attempt-failed`. 성패는 사용자가 표시한다.
- **Credential 기반 RemoteExecution은 좁은 예외다.** SSH/WMIExec/WinRM/secretsdump가 `completed + exit 0`이면
  인증 성공을 직접 입증하므로 Credential→목적 host `reused-credential`과 획득 host→목적 host `pivoted-to`를
  `succeeded`로 투영한다. 실패·timeout·추천·준비 상태는 Access Lineage를 만들지 않는다.
- **클러터는 억제가 아니라 per-node `hidden`으로 관리한다.** 자동 노드화로 그래프가 붐비면 사용자가 노드를 숨길 수 있고
  (`hidden=true`), 숨긴 노드는 Graph/Outline/Attack Path에서 빠진다. 노드는 여전히 존재하므로 **sync가 되살리지 않는다**
  (삭제와 다름). 이는 NodeZero의 "POC 그래프는 전부 저장, v3/v4는 가지치기 렌더" 패턴과 같은 접근이다.
- 모든 투영은 `sourceRef` 기준 멱등이며 **덮어쓰지 않고 병합**: 사용자가 수정한 label/notes/status는 보존, 원천 필드만 갱신.
- **노드 연결 원칙 — 부착 부모는 "가장 구체적인 직접 원인" 노드여야 한다.** 호스트/서비스로의 부착
  (`parent_of(service_id, target_id)`)은 "더 구체적인 원인이 없을 때"의 최후 폴백이지, 일반 규칙이 아니다.
  예: FTP anon finding에서 "익명으로 접속하기"를 눌러 연 세션은 그 finding의 자식이어야지 호스트 밑에 붙으면
  안 된다 — 그 세션이 존재하는 이유 자체가 그 finding이기 때문이다. 이 원칙을 어기면 그래프가 "발견 순서/
  선후관계"가 아니라 "같은 호스트에 있는 것들의 나열"이 되어, 그래프를 도입한 원래 목적(누가 무엇을
  유발했는지 한눈에 보기)이 무의미해진다.
  - **구현 패턴**: 해당 도메인 row에 `graph_parent_node_id` 컬럼을 두고(예: `InteractiveSession`,
    `HashCrackJob`), 생성 엔드포인트의 입력 스키마에 `graph_node_id`(그래프 노드 id, ULID 문자열)를 받아
    그 컬럼에 저장한다. 프런트엔드는 "이 액션을 일으킨, 현재 선택돼 있거나 문맥상 명확한 노드"를 그 필드로
    넘긴다. `sync_from_project`는 이 명시적 부모가 있고(같은 프로젝트, 그 relation의 유효한 source 타입) —
    예를 들어 `attempted`는 `{finding, service, host}`만 source가 될 수 있으므로 credential처럼 항상
    구조적 리프인 타입이 넘어오면 무시 — 있으면 그것을 쓰고, 없을 때만 `parent_of` 폴백을 쓴다.
  - **이 패턴이 아직 없는 곳** (2026-08-14 감사 시점): `Execution`(모든 실행이 항상 서비스/호스트로만
    부착됨 — `sync_from_project`의 execution 루프에 override 자체가 없음), `POST
    /interactive-sessions/manual`(카탈로그 기반 세션 생성 엔드포인트 `POST /interactive-sessions`만 이
    패턴이 있고, 수동 터미널 엔드포인트 `ManualTerminalIn`엔 없음 — Inspector의 `openManualSession`이 이
    경로를 쓰는 다수의 "쉘 열기" 버튼이 전부 이 구멍의 영향을 받는다).
  - **예외**: 최초 발견(스캔이 처음 찾은 서비스, 서비스가 처음 찾은 finding 등)은 "더 구체적인 원인"이
    원래 존재하지 않으므로 호스트/서비스 부착이 정답이다 — 모든 것을 finding/technique에 강제로 매달라는
    뜻이 아니라, **더 구체적인 원인이 실제로 있는데 안 쓰는 경우**만 위반이다.

---

## 7. 비기능 요구사항

- 성능: 노드 500/엣지 1500까지 60fps 목표(Pixi.js WebGL; 대규모 시 d3-force를 Web Worker로 이관). 트리·canonical 계산은 O(N log N).
- 접근성: 색만으로 상태 구분하지 않도록 status 배지 텍스트/아이콘 병행. 애니메이션 off 옵션.
- 결정론: 동일 데이터 → 동일 트리·동일 리포트 번호(정렬 키 고정).
- 로컬 전용/보안: 기존 경계 준수(127.0.0.1 바인딩, 비밀 마스킹, credential opt-in).
- 실행/자동판정 금지: 그래프는 사용자가 입력·표시한 상태만 저장하며 취약 여부·공격경로를 자동 판정하지 않는다(제품 원칙 일치).

---

## 8. 구현 단계(제안)

1. **M1 스키마·저장**: 테이블, project-root/pivoted-to 포함 무결성 검증, CRUD API, export/import.
2. **M2 트리 엔진**: canonical 계산(override 포함) + buildTree + successPaths selector(단위 테스트로 결정론 고정).
3. **M3 Outline 뷰(React DOM)**: 계층 연결선, 상태 배지, expand/collapse 트랜지션, `↗`/`↩` 참조 점프·pulse·Back, 키보드·`/`검색·command palette.
4. **M4 Graph 뷰(Pixi.js)**: d3-force + Graphology 인덱스, 상태색/타입아이콘, 필터·Inspector, status 토글.
5. **M5 Attack Path 뷰(SVG+dagre)**: successPaths 시각화, pivot/재사용 표현, PNG/PDF export.
6. **M6 리포트 export**: md/json/toc, `reports` 모듈 연동.
7. **M7 sync 훅**: nmap/서비스 자동 투영, 대시보드 요약 카드.

---

## 9. 결정 기록 (모든 열린 질문 종결)

| # | 결정 | 반영 위치 |
|---|---|---|
| Q1 | 스코프 = **Project 1:1**, 다중 Target 수용 | §2.1, §4.1 |
| Q2 | 다중 호스트는 project-root 아래. 이동=`pivoted-to`(골격), 재사용=`reused-credential`(참조) | §1.4, §2.1 |
| Q3 | canonical override **허용** (`pinnedCanonicalEdgeId` + 감사) | §2.2, §3.5 |
| Q4 | ~~자동 제안 + 수동 승격~~ → **재결정: Execution 자동 노드화**(성공 자동판정은 안 함) | §6.1 |
| Q15 | 클러터는 per-node `hidden`으로 관리(숨김≠삭제, sync 되살림 방지) | §1.2, §6.1 |
| Q5 | finding `severity`는 **사용자 지정 라벨**. CVSS 자동판정 배제 | §1.3 |
| Q6 | `attempt-failed`와 `blocked`는 **별도 status 유지** | §1.5 |
| Q7 | **Outline=발견순 / Report=성공경로 우선** | §5.1 |
| Q8 | Graph=Pixi.js+d3-force+Graphology, Outline=React DOM+CSS+Motion, Attack Path=SVG | §3.0~3.4 |
| Q9 | Attack Path 렌더러 = **SVG(+dagre)** 확정 | §3.3 |
| Q10 | **Pixi.js 도입 승인** (Obsidian급 Graph의 필수 비용) | §3.0, §7 |
| Q11 | **Objective/Flag 노드 도입** (`objective`/`objectiveKind`, 사용자 지정, 자동추론 안 함) | §1.2, §3.6 |
| — | 적응형 루트(B): 단일 host면 project-root 숨김·host가 시각 루트, 2대+면 project-root 앵커 | §2.1, §3.1 |
| Q12 | NodeZero 흡수: 노드 **provenance** 필드(technique/execution/MITRE stamp) | §1.2, §10 |
| Q13 | NodeZero 흡수: 노드 **`layer`** 필드(timestep, timeline 후보) | §1.2, §10 |
| Q14 | NodeZero 흡수: **Attack Path rollup** selector(`attackPathSummary`) | §3.3, §3.4 |
| — | objective criticality는 **미채택**(OSCP 플래그는 이진, 가치 낮음) | §10 |

열린 질문 없음. 이 명세는 구현 착수 가능 상태다. 이후 변경은 이 표에 delta로 추가한다.

---

## 10. 선행 사례 · 벤치마크 (Prior Art)

"그래프 중심으로 모의해킹 진행을 관리한다"는 UX는 상용 제품에서 이미 검증된 방향이다. 다만 이 도구가 목표로 하는
**"사람의 수동 진행/사고 과정 자체를 knowledge graph로 기록 + Tree/Outline + Attack Path + 리포트"**를 그대로
겹치는 제품은 없다. 상용 다수는 "시스템이 자동 공격 → 결과를 그래프로 시각화"인 반면, 이 도구는
"모의해커의 작업 상태·판단을 워크스페이스로 기록"이다.

| 제품 | 그래프가 나타내는 것 | 유사도 | 우리와의 차이 |
|---|---|---:|---|
| Core Impact (Interactive Attack Map) | 실 pentest 진행·pivot·attack, 제조사가 "primary working space"로 명시 | ★★★★★ | 에이전트/자동 기반, 상용. 우리는 수동·근거 중심 |
| NodeZero (AttackGraph) | 실제 수행된 autonomous attack path. DAG, 노드 Host/Service/Weakness/Credential, 엣지=공격 순서, layer/time | ★★★★★ | 데이터 모델이 매우 유사. 단 자동 수행 |
| Pentera Core | 검증된 attack path + Attack Path Root Cause Analysis | ★★★★ | 자동 검증 중심 |
| BloodHound | **가능한(예측)** identity attack path | ★★★ | 예측·판정형. 우리는 예측·자동판정 안 함(제품 원칙) |
| Metasploit Pro | network topology | ★★ | 토폴로지지, 작업과정 그래프 아님 |

**데이터 모델 정합성 (NodeZero AttackGraph 대비).**
- 노드: 우리 `Host/Service/Finding/Technique/Credential` ≈ NodeZero `Host/Service/Weakness/Credential`.
  ("Weakness" ≈ 우리 "Finding".)
- **결정적 차이 — Technique를 엣지가 아니라 노드로 둔다.** NodeZero는 공격 "행위"를 엣지로 표현하지만,
  워크스페이스에서는 하나의 시도가 status(성공/실패/차단)·notes·evidence·Execution 승격을 갖는 **1급 작업 항목**이어야
  하므로 노드로 승격한다. 이 선택이 "attack map"과 "workspace"를 가르는 핵심이다.
- **작업 그래프는 일반 유향그래프**(순환 허용, `↩`로 표시)지만, 파생된 **Attack Path는 DAG**로 NodeZero AttackGraph와
  동일한 성질을 갖는다(§3.3의 `successPaths`는 순환을 만들지 않음).
- NodeZero의 layer/time → 우리는 이미 `createdAt`을 보유하므로 timeline/temporal 렌더가 가능하다(발전 후보).

**차별점 = workspace 정체성.** `attempt-failed`/`blocked` 상태, `↗ reference`, credential reuse, 수동 canonical,
Execution→Graph 수동 승격, Notes/Evidence 통합 — 전부 단순 attack map이 아니라 작업공간에 속하는 개념이다.
BloodHound식 "가능한 경로 자동 탐색"은 채택하지 않는다. 대신 우리의 `untried` 상태가 곧 사용자가 손으로 세운
"아직 안 해본 가설"이며, 이것이 제품 원칙(자동 판정 금지)을 지키는 방식이다.

**범위·컴플라이언스 경계 (중요).** Core Impact·Metasploit Pro 등은 OSCP 시험 금지 도구다. 이 도구는 그 제품들을
**사용·연동·래핑하지 않으며**, 오직 UX/데이터모델을 **설계 벤치마크로만** 참고한다. 자동 익스플로잇·자동 판정을 하지
않는 수동 기록기라는 점이 (a) 제품 원칙(`docs/ARCHITECTURE.md`), (b) 시험 규정 준수, (c) 상용 대비 차별화를
동시에 만족시킨다. 즉 **차별점과 컴플라이언스 경계가 같은 선**이다.

**참고 출처:** Core Impact 데이터시트/리포팅, Pentera Core, Rapid7 Metasploit, SpecterOps BloodHound(사용자 제공).
NodeZero AttackGraph는 1차 출처(Horizon3 공식 GraphQL API 레퍼런스)로 정밀 조사 완료 →
[docs/RESEARCH_NODEZERO_ATTACKGRAPH.md](RESEARCH_NODEZERO_ATTACKGRAPH.md).

**조사로 검증된 정합성/차이 (요약):**
- NodeZero는 `Host`/`Weakness`/`Credential`을 그래프 노드로 노출한다(우리 host/finding/credential과 강한 정합).
  Service는 엔티티지만 노드로 직접 노출하지 않는다(우리는 service를 1급 노드로 둠 — 워크스페이스 목적상 유지).
- **Technique/action은 노드가 아니라 노드 속성**(`icon_label` + `found_by_module_meta`(MITRE)+명령 로그)이다.
  → 우리는 Technique를 노드로 두는 것을 **의도적 분기**로 유지(조사도 "conscious choice, not shortfall"로 평가).
- **엣지는 무타입 단방향**(from→to, "한 스텝")이고 의미는 도착 노드에 산다. 우리는 **7개 타입 relation**으로 엣지에
  의미를 실음 — 워크스페이스에서 discovered/attempted/blocked를 구분해야 하므로 의도적 분기.
- **AttackGraph는 엄격한 DAG**(문서에 명시). 우리 작업 그래프는 순환 허용(↩ 표시)이되 **파생 Attack Path는 DAG**로
  동일 성질을 만족 → 정합.
- **목표는 1급 개념**: `target_node` + `Impact`/`ImpactType`(DomainCompromise 등) + criticality score. 우리 Q11
  `objective`/`objectiveKind`와 정합(우리는 OSCP 목적상 kind 열거로 단순화, criticality는 선택).
- **시간축 존재**: `time_to_finding`(HH:MM:SS) + timestep layer(`subflow_nodes`, v3). 우리 `createdAt`이 동일한
  시간 원천 → timeline 렌더가 사실상 무료로 가능(발전 후보). (단 `Node.layer_label`은 문서-미검증으로 표시됨.)
- **`blocked-by`는 NodeZero에 없음**: 그들의 그래프는 성공경로 DAG이고 실패는 `Weakness.proof_failure_*`에 남는다.
  우리의 attempt-failed/blocked는 워크스페이스 고유 차별점.

**흡수 후보(조사 권고):** ① 노드 provenance(어느 technique/execution이 이 노드를 만들었는지 stamp, MITRE 포함),
② 노드 layer/time 필드(우리 `createdAt`로 timeline), ③ objective criticality(선택), ④ Attack Path 요약 rollup(노드/크리덴셜/호스트 수).
