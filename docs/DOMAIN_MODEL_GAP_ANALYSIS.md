# Phase 1 도메인 모델 갭 분석

> 2026-08-12 기준 `backend/app/models.py`(816줄)와 `backend/app/modules/**`를 대상으로
> 작성했다. 목적은 목표 도메인 모델(Project/Target/Host/Service/Finding/Credential/
> Evidence/Note/기본 Graph, 9개 객체)과 현재 구현 사이의 차이를 코드 근거와 함께
> 기록하는 것이다. 이 문서는 분석 결과이며 어떤 파일도 수정하지 않았다. Session/
> Privilege/Pivot/Attack Path(Phase 2)와 Faraday 연동(Phase 3)은 범위 밖이다.
>
> 작성 시점 테스트 규모(참고용, 사용자가 언급한 "100개 백엔드/35개 프런트"와는 다르게
> 집계됨): `pytest backend/tests --collect-only`는 431개 테스트를 수집했고,
> `frontend/src`에는 `*.test.ts(x)` 파일이 91개 있다. 정확한 숫자보다 "적지 않은 회귀
> 테스트 자산이 이미 있다"는 사실이 아래 마이그레이션 순서 제안에 반영된 전제다.

## 1. 현재 데이터 구조 인벤토리

`backend/app/models.py`는 모듈별로 나뉘지 않은 단일 파일에 약 38개 ORM 모델을 담고
있다([`ENGINEERING_ONBOARDING.md` §5](ENGINEERING_ONBOARDING.md), §11). 기능 단위로
묶으면 다음과 같다.

| 기능 영역 | 테이블/모델 | 위치 |
|---|---|---|
| Core (Project/Target/Service) | `Project`, `Target`, `Service` | `models.py:7-52` |
| Scan Center | `ScanProfile`, `ScanJob`, `ScanArtifact`, `HostObservation`, `ServiceObservation` | `models.py:72-140` |
| Captured Execution (Service Enumeration 명령) | `Execution` | `models.py:54-70` |
| Interactive Session (PTY) | `InteractiveSession` | `models.py:142-156` |
| Web Testing | `HttpRequest`, `HttpExchange` | `models.py:158-196` |
| Evidence | `Evidence`, `EvidenceImageEdit` | `models.py:198-223`, `375-385` |
| AD Information (Directory) | `DirectoryObject`, `DirectoryRelation` | `models.py:225-248` |
| Tunnels | `Tunnel` | `models.py:250-271` |
| Reports | `Report` | `models.py:273-284` |
| Findings | `FindingTemplate`, `Finding`, `FindingEvidence`, `FindingAsset`, `FindingRetest` | `models.py:286-373` |
| Exploit Research | `ExploitResearch`, `ExploitSource`, `ExploitModification`, `ExploitExecutionRecord`, `ExploitLocalRun` | `models.py:400-520` |
| Post-Exploitation | `RemoteExecution` | `models.py:523-551` |
| Hash Cracking | `HashCrackJob` | `models.py:554-582` |
| Runbooks | `RunbookTemplate`, `RunbookTemplateVersion`, `RunbookStepTemplate`, `RunbookInstance`, `RunbookStepInstance`, `RunbookStepEvidence`, `RunbookStepExecution`, `RunbookActivityEvent`, `RunbookStepCredential`, `RunbookObservation`, `RunbookRecommendationDismissal` | `models.py:585-757` |
| Credentials | `Credential` | `models.py:711-728` |
| Progress Graph | `GraphNode`, `GraphEdge`, `GraphProjectMeta`, `GraphEvent` | `models.py:760-816` |
| Audit / Settings | `AuditEvent`, `AppSetting` | `models.py:387-398` |

Alembic이 아니라 SQLite에 직접 매핑되는 SQLAlchemy 모델이며, 여러 필드가 `TEXT`
컬럼에 JSON 문자열로 저장된다(Service scripts/cpe/tags, Credential.service_names,
Finding.references 등 — `ENGINEERING_ONBOARDING.md` §5).

## 2. Phase 1 객체별 갭 표

| 목표 객체 | 현재 구현 (테이블/모델명, 파일 경로) | 상태 | 비고 |
|---|---|---|---|
| Project | `Project` (`models.py:7-21`) | 일치 | 이름·책임 모두 일치. 다만 exam 전용 필드(`metasploit_target_id`, `metasploit_locked_at`)가 도메인 테이블에 섞여 있음(§4) |
| Target | `Target` (`models.py:23-34`) | 부분일치 | "승인된 스코프"와 "발견된 호스트"가 한 테이블에 의도적으로 합쳐져 있음(§3.1) |
| Host | 없음 — `Target`에 흡수, `HostObservation`은 append-only 로그일 뿐 정규 엔티티가 아님 | 없음 | §3.1 |
| Service | `Service` (`models.py:36-52`) | 일치 | `(target_id, port, protocol)` 기준 정규화. tool-agnostic 필드 구조 양호 |
| Finding | `Finding` + `FindingEvidence` + `FindingAsset` + `FindingRetest` + `FindingTemplate` (`models.py:286-373`) | 일치 | 사람 승인 게이트가 이미 구현됨(§3.2 참고). CVSS·재검증까지 포함해 목표보다 성숙 |
| Credential | `Credential` (`models.py:711-728`) | 일치 | 독립 테이블, project 전역 재사용 가능(Runbook/Post-Exploitation/Hash Cracking에서 공유). 출처 추적은 약함(§3.3) |
| Evidence | `Evidence` (`models.py:198-223`) | 부분일치 | 테이블 자체는 견고하나 실행 결과 stdout/stderr의 "canonical store"가 아님(§3.4) |
| Note | 없음 — 각 테이블의 `notes`/`internal_notes`/`user_notes` 텍스트 컬럼으로 분산 | 없음 | §3.5 |
| 기본 Graph | `GraphNode`/`GraphEdge`/`GraphProjectMeta`/`GraphEvent` (`models.py:760-816`) | 일치(목표 초과) | Host-Service-Credential 관계뿐 아니라 Access Lineage, append-only replay까지 이미 구현됨(§3.6) |

요약: 일치 5 / 부분일치 2 / 없음 2 (총 9개 객체).

## 3. "부분일치" / "없음" 상세

### 3.1 Target — Host 부재 (부분일치 / 없음)

`Target`(`models.py:23-34`)은 `ip`, `hostname`, `os_guess`, `notes`, `updated_at`을
가진 단일 테이블이다. 이는 우연이 아니라 명시적 설계 결정이다 —
[`CONTEXT.md`](../CONTEXT.md) §Assessment Scope는 Target을 "Project 안에서 조사하는
하나의 호스트 또는 IP 기반 대상"으로 정의하고 `Asset`, `Machine` 같은 대체 용어를
명시적으로 피하라고 적어 두었다. 즉 이 코드베이스는 "승인된 스코프"와 "발견된
개별 호스트"를 하나의 개념으로 취급하기로 이미 결정했다.

구체적 증거:

- `Target` 생성은 수동 입력(`/targets`)과 스캔 중 자동 `ensure`(`/targets/ensure`)
  두 경로를 모두 쓴다 — 스코프 등록과 호스트 발견이 같은 테이블·같은 API를 공유한다.
- Nmap/masscan XML ingest(`backend/app/modules/scan_center/service.py:148-165`,
  `ingest_xml`)는 파서가 반환한 여러 호스트 중 `target.ip`와 일치하는 하나만 골라
  쓴다(`hosts = parse_nmap(content); host = next((item for item in hosts if
  item["ip"] == target.ip), hosts[0] if hosts else None)`). `nmap_parser.parse_nmap`
  (`nmap_parser.py:8-16, 52`) 자체는 IP별로 여러 호스트를 담은 리스트를 반환할 수
  있으므로, CIDR 스캔이나 masscan 다중 호스트 결과에서 발견된 나머지 IP는 폐기되고
  별도 `Target`/`Host` row로 승격되지 않는다.
- `HostObservation`(`models.py:114-122`)은 `scan_job_id` 단위로 매 ingest마다
  무조건 새로 추가되는 로그다(`service.py:163-165`) — 중복 제거나 "이 호스트는 이미
  안다"는 병합 없이 쌓이기만 한다. 정규 Host 엔티티로 승격되는 코드 경로가 없다.

목표 모델처럼 Target(승인된 스코프)과 Host(그 스코프 안에서 발견된 개별 호스트, 1:N)를
분리하려면 스키마 변경뿐 아니라 `CONTEXT.md`의 Target 정의 자체를 갱신해야 한다 —
현재 문서화된 도메인 언어와 정면으로 부딪히는 지점이다.

### 3.2 Finding — 승인 구조는 이미 존재

목표 모델의 "사람이 승인해야 확정되는 구조"는 이미 상당 부분 구현돼 있다.
`Finding.status`는 DB 컬럼상 자유 문자열(`String(30)`, `models.py:331`)이지만 입력
스키마에서 `Literal["Draft", "Confirmed", "Needs Review", "Remediated", "Accepted
Risk", "False Positive"]`로 제한된다(`backend/app/schemas.py:404`, bulk update는
`backend/app/modules/findings/router.py:308-309`에서 같은 allow-list를 재적용).
스캔에서 자동 생성되는 Finding도 `status="Needs Review"`로 시작하며 `Confirmed`가
아니다(`scan_center/service.py:270-278`) — 자동 판정이 아니라 검토 대기 상태로
들어간다는 점에서 목표 원칙과 일치한다. 다만 상태 전이 자체를 강제하는 상태 머신은
없고(`Draft`에서 바로 `Remediated`로도 갈 수 있음), Evidence 링크도 0개로 생성 가능해
(`schemas.py:383-408`의 `evidence` 필드에 `min_length` 없음) traceability가 강제되지
않고 관례에 의존한다.

### 3.3 Credential — 구조는 독립적이나 출처 추적이 느슨함

`Credential`(`models.py:711-728`)은 자체 PK를 가진 독립 테이블이며 `target_id`/
`service_id`가 nullable이라 project 전역에서 재사용 가능하다. 생성 지점은 두 곳뿐이다.

- 수동 입력: `backend/app/modules/runbooks/credentials_router.py:47`
- Hash Cracking 승격: `backend/app/modules/hash_cracking/router.py:266-269` —
  `source_kind="hash_crack", source_detail=f"Hash crack #{row.id} · ..."`

두 경우 모두 `source_kind`/`source_detail`(`models.py:723-724`)이 자유 텍스트다.
즉 이 Credential이 어떤 `HashCrackJob`/`RemoteExecution`/`Execution`에서 나왔는지는
실제 FK가 아니라 사람이 읽을 문자열(예: `"Hash crack #42 · ..."`)로만 남는다 —
Evidence traceability 원칙(각 객체가 어떤 Command/Tool/Evidence에서 나왔는지 추적
가능해야 함)이 Credential에는 소프트하게만 적용된다.

### 3.4 Evidence — 실행 결과의 canonical store가 아님

`Evidence`(`models.py:198-223`)는 `sha256`, `file_path`, `source_type`/`source_id`
(약한 참조), `acquired_at` 등 목표 모델이 요구하는 필드를 충분히 갖췄다. 그러나 실제
명령 실행의 원본 stdout/stderr는 기본적으로 Evidence를 거치지 않고 각 실행 전용
테이블에 직접 저장된다.

- `Execution.stdout`/`Execution.stderr`(`models.py:61-62`) — 텍스트 그대로 보관
- `RemoteExecution.stdout_path`/`stderr_path`(`models.py:540-541`) — 파일 경로만 보관
- `ExploitLocalRun.stdout_path`/`stderr_path`(`models.py:508-509`)
- `InteractiveSession.log_path`(`models.py:155`), `Tunnel.log_path`(`models.py:267`)

이들 각각은 `evidence_id`라는 **nullable** FK(`RemoteExecution.evidence_id` at
`models.py:549-550`, `ExploitLocalRun.evidence_id` at `516-517`,
`HashCrackJob.evidence_id` at `580-581`)로 Evidence에 선택적으로만 연결된다. Scan
Center는 `capture_scan_evidence`(`scan_center/service.py:220-292`)가 스캔 산출물과
positive NSE 결과를 자동으로 Evidence화하지만, 이는 Nmap 전용 로직이고 다른 실행
종류(Post-Exploitation, Exploit Research, Hash Cracking, 대화형 세션)의 출력은 사용자가
명시적으로 "Evidence로 저장" 액션을 눌러야 Evidence 테이블에 들어간다. 즉 Evidence는
있지만 "모든 원본 출력이 반드시 여기로 모인다"는 보장은 없다 — §4의 도구 중심 저장
패턴과 직결된다.

### 3.5 Note — 독립 엔티티 없음

`grep -rn "class Note"`는 아무것도 찾지 못했고, 별도 Note 라우터도 없다. 자유 메모는
아래처럼 소유 테이블에 텍스트 컬럼으로 흩어져 있다.

| 테이블 | 컬럼 | 위치 |
|---|---|---|
| `Target` | `notes` | `models.py:32` |
| `Service` | `notes` | `models.py:51` |
| `DirectoryObject` | `notes` | `models.py:234` |
| `DirectoryRelation` | `notes` | `models.py:247` |
| `Credential` | `notes` | `models.py:727` |
| `RunbookStepInstance` | `notes` | `models.py:674` |
| `Finding` | `internal_notes` | `models.py:336` |
| `FindingRetest` | `notes` | `models.py:371` |
| `ExploitLocalRun` | `user_notes` | `models.py:519` |
| `GraphNode` | `notes` | `models.py:770` |

각 메모는 소유 레코드 하나에 종속돼 있어 고유 id·작성 시각·작성자·첨부 Evidence를
가진 독립 객체로 조회하거나 여러 대상에 걸쳐 검색할 수 없다(Operations 전역 검색이
각 테이블의 `notes` 컬럼을 개별적으로 흝을 뿐, 통합 Note 테이블을 조회하는 것이
아니다).

### 3.6 Graph — 이미 목표를 넘어섬

`GraphNode.type`은 `{"project-root", "operator", "host", "service", "finding",
"technique", "credential"}` 집합으로 서비스 레이어에서 검증된다
(`backend/app/modules/graph/service.py:92-95, 205-206`; Pydantic에서는 강제되지 않고
`schemas.py`의 `NodeIn.type`은 단순 `str`이다). `sync_from_project`
(`graph/service.py:303-548`)가 `Target`을 `type="host"` 노드로, `Service`를
`type="service"` 노드로 그대로 투영하므로 목표 모델이 요구하는 최소 구조(Host-Service-
Credential을 노드/엣지로 표현)는 이미 만족한다. 게다가 완료된 Lateral
Access(SSH/WMIExec/WinRM/secretsdump)에서 `reused-credential`/`pivoted-to` 엣지를
파생시키는 로직, append-only `GraphEvent` 기반 Attack Replay까지 있어 Phase 1이
요구하는 "기본" 수준을 초과한다. 참고로 여기서 쓰이는 `host` 노드 타입은 §3.1에서
설명한 대로 실제로는 `Target` row를 가리킨다 — Host 엔티티가 스키마에 생기면 Graph의
`host` 노드가 가리키는 대상도 `Target`에서 `Host`로 바뀌어야 한다.

## 4. "도구 중심" 저장 패턴 (tool-agnostic 원칙과 충돌)

1. **Scan Center 전용 발견 파이프라인.** `ScanJob`/`ScanArtifact`/`HostObservation`/
   `ServiceObservation`(`models.py:84-140`)은 Nmap/masscan 스캔에 종속된 테이블이다.
   `HostObservation`의 `ip`/`hostname`/`os_guess`, `ServiceObservation`의
   `port`/`protocol`/`state`/`product`/`version`/`scripts`/`cpe`/`tls`/
   `detection_evidence`는 각각 `Target`/`Service`의 필드를 거의 그대로 복제한 형태다.
   "Host가 발견됐고 Source는 Nmap이다"처럼 도구 이름이 값(속성)이 되는 정규화가 아니라,
   "Nmap/masscan 스캔"이라는 도구 카테고리 자체가 테이블 구조(`scan_job_id` FK)로
   박혀 있다. 수동으로 호스트를 등록하거나 다른 스캐너 결과를 가져오는 경로는 이
   Observation 트레일을 거치지 않고 `core` 모듈의 Target/Service CRUD를 직접
   호출한다 — 즉 "어떤 소스로 발견됐는가"가 일관된 필드가 아니라 어떤 API 경로를
   탔는지에 암묵적으로 의존한다.

2. **실행 기록 테이블이 도구 카테고리별로 병렬 존재.** `Execution`(범용 catalog 명령),
   `RemoteExecution`(post-exploitation), `ExploitLocalRun`(exploit research),
   `HashCrackJob`(hashcat), `InteractiveSession`(PTY)은 모두 개념적으로 "승인된 명령
   1회 실행 + stdout/stderr + 상태"라는 같은 모양이지만 각자 독립된 스키마와
   `prepared → running → completed/failed/...` 상태 문자열을 따로 정의한다
   (`ENGINEERING_ONBOARDING.md` §8 표 참고). 도구 카테고리가 바뀔 때마다 테이블이
   하나씩 늘어나는 구조라, 지원하지 않는 새 도구가 추가될 때 기존 테이블 중 어느 것도
   "그냥 재사용"할 수 없고 매번 유사한 테이블을 새로 만들어야 한다.

3. **Evidence가 실행 결과의 기본 목적지가 아님.** §3.4에서 설명한 대로, stdout/stderr는
   기본적으로 실행 전용 테이블(`Execution.stdout`, `RemoteExecution.stdout_path` 등)에
   저장되고 Evidence로의 연결은 선택적(nullable FK 또는 수동 업로드)이다. 자동 캡처
   로직(`capture_scan_evidence`)도 Nmap 스캔에만 존재하고 다른 도구에는 대응하는
   자동 캡처가 없다.

4. **Credential 출처가 자유 텍스트.** §3.3에서 설명한 대로 `source_kind`/
   `source_detail`은 실제 FK가 아니라 사람이 읽을 문자열이라, 어떤 도구/Execution이
   이 Credential을 만들었는지 프로그램적으로 조회할 수 없다.

## 5. Migration 필요 항목 (우선순위 순, 점진적 마이그레이션 전제)

아래 순서는 한 번에 스키마를 갈아엎지 않고 객체 단위로 순차 적용하는 것을 전제로
한다. 각 단계는 이전 단계가 하위 호환 상태로 완료된 뒤 시작할 수 있도록 배치했다.
Session/Privilege/Pivot/Attack Path, Faraday 연동은 Phase 2/3 범위이므로 제외했다.

1. **Evidence를 실행 결과의 기본 목적지로 만들기 (Evidence 확장, 스키마 파괴 없음).**
   `RemoteExecution`/`ExploitLocalRun`/`HashCrackJob`이 실행 종료 시 stdout/stderr를
   무조건 `Evidence` row로 생성하고 `evidence_id`를 채우도록 각 모듈의 완료 처리
   경로만 바꾼다. 기존 `stdout_path`/`stderr_path` 컬럼은 당장 제거하지 않고 유지해도
   된다(하위 호환). 위험이 가장 낮고(신규 컬럼/테이블 없음, FK는 이미 존재), Finding·
   Credential traceability 개선의 전제 조건이라 가장 먼저 손댈 항목으로 추천한다.

2. **Credential 출처를 구조화(soft FK → 실제 FK 또는 구조화 필드).**
   `source_kind`/`source_detail` 문자열 대신 `source_execution_kind` +
   `source_execution_id` 같은 명시적 참조 쌍을 추가하고, 기존 자유 텍스트는 표시용
   `source_detail`로 남긴다(가산적 변경, 기존 데이터 깨지지 않음). 1번이 끝나야
   "이 Credential은 이 Evidence/Execution에서 나왔다"는 사슬이 실제로 의미를 가진다.

3. **Note를 독립 테이블로 분리.**
   신규 `Note` 테이블(`id`, `project_id`, 선택적 `target_id`/`service_id`/
   `credential_id` 등 polymorphic 참조, `body`, `created_at`, `author`)을 추가하고,
   기존 `notes`/`internal_notes`/`user_notes` 컬럼은 즉시 제거하지 않는다. 프런트엔드
   화면별로 순차적으로 "메모 작성" UI를 새 Note API로 옮기고, 레거시 컬럼은 읽기
   전용으로 유지하다가 데이터 이관 스크립트로 옮긴 뒤 별도 PR에서 제거한다. 영향
   범위가 프런트 다수 화면에 걸치므로 다른 항목보다 뒤에 배치했다.

4. **Host를 Target에서 분리 (가장 크고 가장 나중에).**
   `Host` 테이블을 신설해 `target_id`(스코프) 1:N `host`(발견된 개별 IP) 관계로
   바꾼다. 이는 (a) `CONTEXT.md`의 Target 정의 갱신, (b) `nmap_parser`/`ingest_xml`이
   여러 호스트를 폐기하지 않고 각각 Host로 적재하도록 하는 변경, (c) `Service`의
   FK를 `target_id`에서 `host_id`로(혹은 둘 다 허용하는 과도기 스키마로) 바꾸는 변경,
   (d) Graph의 `host` 노드가 `Target` 대신 `Host`를 가리키도록 하는 변경, (e) 프런트
   엔드 전역의 "Project → Target → Service" 3단 네비게이션을 4단으로 바꾸는 변경까지
   묶여 있다. 백엔드 92개 테스트 이상이 `Target.ip`/`Target.hostname`을 직접 참조할
   가능성이 높고, `oscp-target-change` custom event를 듣는 프런트 워크스페이스 10곳
   이상이 영향을 받는다. 스키마·도메인 언어·양쪽 코드베이스를 모두 건드리는 항목이라
   가장 리스크가 크며, 1~3번으로 확보한 여유(정리된 Evidence/Credential/Note 경로)
   위에서 별도 브랜치로 단계적으로(먼저 `Host` 테이블 추가 + 병행 쓰기 → 읽기 경로
   전환 → `Target`에서 호스트 필드 제거) 진행할 것을 권장한다.

Scan Center의 `ScanJob`/`HostObservation`/`ServiceObservation`을 진짜 tool-agnostic
"discovery event" 모델로 일반화하는 작업(§4-1)은 Host 분리(4번)와 강하게 얽혀 있으므로
같은 마이그레이션에 묶어 진행하는 편이 이중 작업을 피할 수 있다.
