# Runbook Product Research

조사일: 2026-07-30  
범위: PlexTrac Runbooks 제품 흐름과 OSCP Workspace의 built-in service runbook 설계  
출처 정책: 제품 소유자의 공식 문서·공식 저장소만 사용했다. 아래의 제품 권고는 출처에
명시된 사실과 현재 저장소의 정책 경계를 결합한 설계 판단이며, PlexTrac 기능의 복제
명세가 아니다.

## 결론

Runbook의 첫 화면을 빈 작성기로 시작하는 것은 PlexTrac의 대표적인 사용 흐름과 다르다.
PlexTrac는 빈 Test Plan과 기존 Test Plan을 시작점으로 함께 제공하고, 이후 재사용 가능한
Procedure를 검색·선택·삭제·재정렬하게 한다
([Creating a Test Plan](https://docs.plextrac.com/plextrac-documentation/product-documentation/runbooks/managing-test-plans/creating-a-test-plan)).
또한 모든 사용자가 접근하고 삭제할 수 없는 `PlexTrac Curated` 저장소를 제공한다
([RunbooksDB Home Page](https://docs.plextrac.com/plextrac-documentation/product-documentation/content-library/runbooksdb/runbooksdb-home-page)).

따라서 OSCP Workspace의 기본 흐름은 다음이어야 한다.

1. 발견된 Target/Service에 맞는 **발행된 built-in runbook 추천**을 먼저 보여준다.
2. 사용자가 근거·단계·위험도를 검토하고 **적용**하여 불변 Instance snapshot을 만든다.
3. Step의 명령은 바로 실행하지 않고 기존 preview/승인 경계로 보낸다.
4. 사용자가 결과·Evidence·상태를 직접 판정한다.
5. 수정이 필요할 때만 built-in을 **복제하여 편집**하고, 완전한 새 작성은 보조 경로로 둔다.

이는 현재 저장소의 “추천 → 사용자 적용 → command 검토 → 승인 → 사용자 판정” 계약
([RUNBOOK_ROADMAP.md](./RUNBOOK_ROADMAP.md)) 및 모든 명령을 사용자가 선택·확인해야 한다는
시험 경계([OSCP_POLICY.md](./OSCP_POLICY.md))와 일치한다.

## PlexTrac 공식 동작

| 관심사 | 공식 동작 | OSCP Workspace에 주는 의미 |
|---|---|---|
| 기본 콘텐츠 | `PlexTrac Curated`는 모든 사용자가 접근하는 비삭제 저장소이고 공식 문서는 1,500+ ATT&CK Procedure를 설명한다. 현재 제품 페이지는 500+ pre-built Procedure라고 표현한다. 숫자는 문서 시점/범위가 다를 수 있어 고정 제품 요구로 삼지 않는다. ([DB](https://docs.plextrac.com/plextrac-documentation/product-documentation/content-library/runbooksdb/runbooksdb-home-page), [제품 페이지](https://plextrac.com/platform/runbooks/)) | 개수 경쟁보다 필수 서비스의 작고 검증된 built-in 묶음을 제공하고 coverage를 측정한다. |
| 계층 | Repository는 콘텐츠/접근 경계이고, Procedure는 실행 단계, Technique는 Procedure 묶음, Tactic은 Technique 묶음, Methodology는 Tactic 묶음이다. ([DB](https://docs.plextrac.com/plextrac-documentation/product-documentation/content-library/runbooksdb/runbooksdb-home-page), [Methodology](https://docs.plextrac.com/plextrac-documentation/product-documentation/content-library/runbooksdb/methodologies)) | OSCP MVP는 `Template → Version → ordered Step`을 유지한다. Purple Team용 Tactic/Technique 계층을 억지로 도입하지 않고 external references/tags로 연결한다. |
| Procedure 품질 | Procedure에는 title, ID, repository, description, 1개 이상의 실행 단계가 필요하고 ATT&CK 연결, tag, step success criteria를 지원한다. 문서는 목표·지시·예상 결과/변형·안전 주의·탐지/완화 지침을 권한다. ([Creating a Procedure](https://docs.plextrac.com/plextrac-documentation/product-documentation/content-library/runbooksdb/procedures)) | 각 Step에 목적, command ref, 예상 Observation, 안전 설명, 수동 완료 기준을 제공한다. |
| Test Plan 생성 | blank 또는 existing plan을 선택하고 Procedure를 필터/선택한 후 삭제·재정렬하고 coverage를 검토한다. ([Creating a Test Plan](https://docs.plextrac.com/plextrac-documentation/product-documentation/runbooks/managing-test-plans/creating-a-test-plan)) | 기본 진입점을 “추천/Library에서 적용”으로 바꾸고 작성기는 명시적 보조 액션으로 둔다. |
| Engagement | 기존 Test Plan을 선택하면 세부 정보와 Procedure가 채워지며 시작 전에 편집할 수 있다. ([Starting an Engagement](https://docs.plextrac.com/plextrac-documentation/product-documentation/runbooks/engagements/starting-an-engagement)) | Version에서 Instance snapshot을 만드는 현재 모델이 적합하다. 실행 중 template 변경이 과거 작업을 바꾸면 안 된다. |
| 복제·맞춤화 | ready-made 콘텐츠를 copy/duplicate하여 맞춤화하고 자체 Procedure/Tactic/Technique/Methodology를 관리한다. ([제품 페이지](https://plextrac.com/platform/runbooks/)) | built-in은 읽기 전용이며 `복제하여 편집`만 허용한다. 사용자 사본은 upstream update와 자동 병합하지 않는다. |
| Versioning | 표준 템플릿이 최신 MITRE/Atomic Red Procedure의 versioning을 지원한다고 설명한다. ([제품 페이지](https://plextrac.com/platform/runbooks/)) | `origin`, `upstream_id`, `upstream_version`, `content_hash`, `installed_at`를 기록하고 upgrade preview 후 새 Version을 발행한다. |
| Import | 공식 통합 목록은 Runbooks용 MITRE Engenuity YAML을 명시하고, BlindSPOT은 runbook 생성/갱신과 simulation detail 채우기를 지원한다. ([Imports](https://docs.plextrac.com/plextrac-documentation/product-documentation-1/integrations-and-file-imports), [BlindSPOT](https://docs.plextrac.com/plextrac-documentation/product-documentation-1/integrations-and-file-imports/blindspot)) | 현재 JSON v1 import는 유지하되 엄격한 schema/크기/command-ID 검증을 적용한다. 외부 포맷 어댑터는 시험 MVP 밖으로 둔다. |
| 권한 | Repository는 Open, Managed, Private 접근 모델을 제공한다. ([Repository Types](https://docs.plextrac.com/plextrac-documentation/product-documentation/content-library/types-of-repositories)) | 단일 사용자 MVP에서는 built-in/user origin만 구분한다. 다중 사용자 전까지 RBAC를 선행 구현하지 않는다. |

## 공식 지식 원천 비교

| 원천 | 제공하는 것 | 적합한 사용 | 그대로 가져오면 안 되는 것 |
|---|---|---|---|
| Nmap NSE | discovery, version, auth, brute, vuln, exploit 등 스크립트와 `safe`/`intrusive` 등 category를 제공한다. 일부 default script도 intrusive일 수 있고 third-party script는 sandbox되지 않는다. ([NSE manual](https://nmap.org/book/man-nse.html), [categories](https://nmap.org/book/nse-usage.html)) | `services.yaml` command ref의 공식 근거, 서비스/포트별 applicability, risk metadata. NSE `portrule`도 port state/number/service에 따라 실행 대상을 정한다. ([Script format](https://nmap.org/book/nse-script-format.html)) | `-sC`, `all`, category 전체를 안전하다고 간주하거나 자동 실행하지 않는다. brute/intrusive/exploit/dos/external은 명시적 위험 표시와 별도 승인 대상이다. |
| OWASP WSTG | 웹/웹서비스 보안 테스트의 포괄적 framework와 Information Gathering부터 API Testing까지의 taxonomy를 제공한다. 공식 사이트는 version 없는 ID/link가 변할 수 있으므로 versioned link를 권한다. ([WSTG](https://owasp.org/www-project-web-security-testing-guide/), [v4.2 framework](https://owasp.org/www-project-web-security-testing-guide/v42/3-The_OWASP_Testing_Framework/0-The_Web_Security_Testing_Framework)) | HTTP/HTTPS runbook의 coverage map과 사람이 수행하는 점검 설명. `WSTG-v42-...` ID와 versioned URL을 source reference로 저장한다. | WSTG 항목을 곧바로 실행 가능한 shell command로 축소하거나, 모든 웹앱에 전 항목을 추천하지 않는다. 앱 context가 필요한 항목은 manual step이다. |
| MITRE ATT&CK | tactic은 목적(why), technique은 방식(how), sub-technique은 더 구체적인 행위다. 공식 데이터는 STIX 2.0/2.1 및 TAXII로 제공되고 versioned bundle이 있다. ([Resources](https://attack.mitre.org/resources/), [Data and Tools](https://attack.mitre.org/resources/attack-data-and-tools/), [STIX repository](https://github.com/mitre-attack/attack-stix-data)) | 선택적 분류/상호운용 metadata, 안정적 external ID, pinned upstream release. | ATT&CK는 service enumeration checklist가 아니다. ATT&CK 매핑 자체를 추천 또는 실행 근거로 사용하지 않는다. |
| Atomic Red Team | ATT&CK에 매핑된 작고 portable/reproducible한 테스트 library다. 각 Technique 폴더의 YAML이 test 정의이고 Markdown 표현도 제공된다. ([Atomic repository](https://github.com/redcanaryco/atomic-red-team), [Invoke repository](https://github.com/redcanaryco/invoke-atomicredteam)) | 향후 별도 Purple Team catalog importer의 구조 참고: stable test ID, input args, prerequisites, executor, cleanup. | OSCP service enumeration built-in으로 자동 설치/실행하지 않는다. 공식 실행 문서도 테스트 이해와 권한을 요구하며 definitions, payloads, executor를 구분한다. ([Getting Started](https://www.atomicredteam.io/docs/invoke-atomicredteam/getting-started)) |

ATT&CK는 계속 개정된다. 조사 시점 공식 changelog의 최신 표기는 19.1(2026-05-12)이다
([ATT&CK changelog](https://attack.mitre.org/resources/changelog.html)). 따라서 `latest`를 저장하지
말고 가져온 release를 고정해야 한다. ATT&CK 콘텐츠를 배포할 경우 공식 이용 조건의
저작권 표시와 attribution도 보존해야 한다
([ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/)).

## Built-in service runbook 설계

현재 `backend/templates/services.yaml`은 Target identity, FTP, SSH, Telnet, SMTP, DNS,
HTTP, SMB/RPC, NFS, LDAP/Kerberos, databases, RDP/WinRM, SNMP, IMAP/POP3, VNC,
MongoDB, Rsync, Unknown 명령군을 이미 제공한다. 새 built-in은 명령 문자열을 복사하지
않고 이 catalog의 안정적인 command ID만 참조해야 한다.

### 권장 seed

| Tier | Template | 기본 Step 방향 | 위험 경계 |
|---|---|---|---|
| 0 | Target identity, Unknown service | hostname/OS/service version 식별, 관찰 기록 | OS detection의 sudo 및 추가 probe를 preview에 표시 |
| 1 | FTP, SSH, Telnet, SMTP, DNS | banner/capability/system info, anonymous 또는 수동 접속, 관찰 기록 | credential guessing은 별도 Step이며 기본 비활성 |
| 1 | HTTP/HTTPS | header/technology/auth surface 확인 후 WSTG v4.2 기반 수동 조사 checklist로 이동 | crawler, brute, active vulnerability test 자동화 금지 |
| 1 | SMB/RPC, NFS, LDAP/Kerberos | 공개 share/export/domain/capability 열거 | 인증·계정 잠금·민감 directory 접근을 별도 승인 |
| 1 | Database, SNMP, IMAP/POP3, VNC, MongoDB, Rsync | version/capability/anonymous exposure 확인 | default credential/community guessing은 high-risk |
| 1 | RDP/WinRM | protocol/security capability 확인과 수동 client handoff | 인증 시도와 remote execution을 분리 |

각 seed는 최소한 다음 필드를 가져야 한다.

- 안정적 `builtin.<service>.<purpose>` 논리 ID와 monotonically increasing Version
- `origin=builtin`, source title, source URL, source version/date, content hash
- service names, ports, protocol과 추천 priority/reason
- Step title, 목적/설명, ordered command refs, 예상 Observation, 수동 완료 기준
- `risk`, `requires_credentials`, `may_lock_account`, `intrusive`, `external_network`,
  `requires_sudo`, `interactive`를 command catalog에서 계산한 표시용 summary
- source command가 사라진 경우 과거 snapshot은 표시하되 실행은 차단하는 상태

## 추천과 실행 UX

추천은 결정을 대신하지 않고 설명 가능한 후보를 좁혀야 한다.

1. 정확한 service name match를 1순위, well-known port match를 2순위로 둔다.
2. service와 port가 충돌하면 “낮은 신뢰도”로 표시하고 Unknown identity runbook을 함께 제안한다.
3. 추천 카드에 `서비스명 일치`, `포트 21 일치`처럼 현재 API의 reason을 그대로 표시한다.
4. 최신 발행 Version만 추천하되 적용 시 Version/Step을 snapshot한다.
5. 같은 service fingerprint/version의 dismiss와 적용 상태를 유지하고, fingerprint가 바뀌면 다시 제안한다.
6. `적용`은 checklist 생성만 수행한다. 실행, HTTP 요청, status 완료는 발생시키지 않는다.
7. Step에서 command를 선택하면 command catalog를 다시 조회해 최종 문자열·대상·risk·sudo·
   timeout을 preview하고, 기존 일회성 승인을 받아 한 번만 실행한다.
8. exit code와 parser output은 Observation 후보일 뿐, Step status나 Finding을 자동 확정하지 않는다.

이 흐름은 Nmap이 `safe`라고 분류해도 부작용을 보장하지 않으며 일부 default도 intrusive일
수 있다는 공식 경고([NSE categories](https://nmap.org/book/nse-usage.html))를 반영한다.

## Update, clone, import 계약

- built-in Template는 archive/edit/delete를 금지하고 `복제하여 편집`만 제공한다.
- upstream seed 변경은 기존 Version을 수정하지 않고 새 Version으로 설치한다.
- 이미 적용한 Instance는 자동 upgrade하지 않는다. diff(추가/삭제/변경 Step 및 command ref)를
  보여주고 사용자가 새 Instance 또는 새 Version 적용을 선택한다.
- clone은 현재 최신 Version의 독립 user Template를 만들며 source template/version을 기록한다.
- import는 schema version, byte/step 제한, unknown/duplicate command ID, 위험 metadata,
  URL/secret-like value를 검사하고 preview 후 발행한다. Import 자체가 실행 권한을 부여하지 않는다.
- MITRE STIX, Atomic YAML, WSTG taxonomy는 서로 다른 의미를 가지므로 하나의 범용 importer로
  해석하지 않는다. 별도 adapter와 provenance를 사용한다.

## 구현 우선순위와 완료 기준

### P0 — 첫 사용 경험

- migration/seed에서 모든 핵심 service built-in을 idempotent하게 설치한다.
- Library 기본 탭을 `추천`으로 하고 Target/Service 선택 시 빈 작성기보다 추천 카드를 먼저 보인다.
- 각 카드에서 단계 preview, 추천 근거, risk summary, 한 번의 `적용`을 제공한다.
- built-in 상세에는 `복제하여 편집`, user template에는 편집/발행/archive를 제공한다.
- zero-state는 “직접 작성”이 아니라 scan/import 또는 built-in 탐색으로 안내한다.

완료 기준: 새 DB에서 FTP/21 Service를 만들면 `FTP 기본 열거`가 사용자 입력 없이 나타나고,
적용해도 어떠한 명령도 실행되지 않으며, Step 실행에는 기존 preview/승인이 반드시 필요하다.

### P1 — 신뢰와 유지보수

- provenance/version/hash, update availability, immutable upgrade diff를 구현한다.
- command ref 유효성 및 seed coverage를 CI에서 검증한다.
- service alias/port match와 low-confidence/Unknown fallback 테스트를 추가한다.
- built-in 수정/삭제 차단, clone 독립성, Instance snapshot 불변성 회귀 테스트를 추가한다.

### P2 — 표준 연결

- HTTP runbook에 versioned WSTG references와 category filter를 추가한다.
- 필요할 때만 pinned ATT&CK STIX metadata importer를 추가한다.
- Atomic Red Team은 OSCP 실행 모드와 분리된 별도 catalog/기능으로 검토한다.

## 하지 않을 것

- scan 결과만으로 Runbook을 자동 적용하거나 Step을 자동 완료하지 않는다.
- 추천에서 command를 자동 실행하지 않는다.
- 위험한 NSE category나 Atomic test를 “공식 콘텐츠”라는 이유로 신뢰하지 않는다.
- Finding, 성공 여부, 취약성, 공격 경로를 자동 판정하지 않는다.
- 현재 OSCP 제품 요구와 무관한 PlexTrac의 Purple Team 전체 계층/RBAC를 먼저 복제하지 않는다.

