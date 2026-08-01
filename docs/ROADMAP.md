# Product Roadmap

기준일: 2026-07-30

## 제품 방향

OSCP Workspace는 승인된 단일 사용자 평가를 위한 로컬 작업대다. 제품의 중심은 더 많은
공격을 자동화하는 것이 아니라, 사용자가 범위와 최종 동작을 통제하면서 조사 누락을 줄이고
수행 사실과 근거를 재구성 가능하게 남기는 것이다.

앞으로도 다음 원칙을 유지한다.

- 관찰과 판정을 분리한다.
- 추천, 적용, 실행을 서로 다른 사용자 결정으로 유지한다.
- 원본 출력과 불변 snapshot을 보존한다.
- 명령은 서버가 검증된 카탈로그에서 다시 만들고 매번 사용자가 승인한다.
- AI 분석, 자동 취약점 판정, 자율 공격 체인과 자동 셸 획득은 제품 범위에 넣지 않는다.

## 현재 구현 기준선

| 영역 | 구현 상태 | 현재 제공 범위 |
|---|---|---|
| Project / Target | 완료 | 등록·수정·삭제, 현재 범위 선택 |
| Scan Center | 완료 | Nmap preview, 큐·SSE·중단, XML import, 원본·해시, 비교·내보내기 |
| Service Enumeration | 완료 | 서비스별 명령 catalog, preview·승인·실행, 결과·PTY, 메모·태그 |
| Web Testing | 완료 | 사용자 작성 HTTP 요청, 반복 전송, proxy/TLS, 응답 기록·비교 |
| Exploit Research | 완료 | SearchSploit 후보, 원본/working copy, diff·해시, 승인된 로컬 실행 |
| Runbooks | 완료(P0/P1 기반) | 기본 18종, 추천·적용, 불변 version/instance, 진행률·연결·Finding |
| Evidence | 완료 | 파일·출력·메모, provenance·해시·민감도, ZIP manifest |
| AD Information | 완료 | 관찰 객체·관계, 필터, CSV/JSON import |
| Sessions / Tunnels | 완료 | 승인된 SSH forwarding, PTY, 상태·로그·종료 |
| Reports | 완료 | Markdown 작성, Evidence 연결, HTML/PDF/Markdown export |
| Operations / VPN | 완료 | 검색·감사·백업, OVPN 검증, NetworkManager와 tun0 상태 |

“완료”는 현재 정의된 로컬 단일 사용자 범위를 뜻한다. 다중 사용자 SaaS, 협업, 자율화까지
완성했다는 의미가 아니다.

## 다음 우선순위

### P0 — 신뢰성과 일상 사용성

목표는 새 기능보다 매일 안심하고 사용할 수 있는 상태다.

- 큰 `main.py`와 거대 Workspace 컴포넌트를 기능별 service/API/UI 모듈로 점진 분리
- 공통 API client, 오류 표현과 React Query key 정리
- 전체 사용자 흐름 통합 테스트: scan import → 추천 → runbook → evidence → report
- 백업 복구 명령과 검증 가능한 restore 절차
- SQLite foreign key, orphan link, 중복 command ID와 데이터 무결성 검사 강화
- 실행·세션·스캔 재시작 복구와 실패 메시지 일관성 개선
- 작은 노트북 화면, 키보드, focus, 긴 출력과 empty state 접근성 회귀 테스트

완료 기준:

- 깨끗한 DB와 기존 DB 모두 한 번의 설치/시작으로 head migration에 도달한다.
- 핵심 흐름이 브라우저 통합 테스트로 재현된다.
- 백업을 별도 임시 환경에 복원하고 주요 레코드와 파일 해시가 일치한다.

### P1 — Runbook 품질과 조사 연결

- 기본 Runbook을 제품별로 더 세분화하고 command coverage 테스트 추가
- 추천 근거에 service-name/port 신뢰도와 충돌 상태 표시
- 적용 전 Step preview 및 risk/sudo/interactive 요약
- 기본 Runbook provenance, content hash, source version과 update diff
- 이미 적용한 Instance는 고정한 채 새 Version 적용 여부를 사용자가 선택
- Service Enumeration에서 관련 Step으로 돌아오는 양방향 navigation
- Finding에 영향, 재현 절차, 완화, 보고서 포함 여부를 점진적으로 추가
- HTTP 절차에 version이 고정된 OWASP WSTG reference 연결

완료 기준:

- command ID가 사라진 과거 Step은 열람 가능하지만 실행은 명확히 차단된다.
- 기본 콘텐츠 업데이트가 기존 Instance를 변경하지 않는다.
- 추천 이유와 위험 정보를 적용 전에 확인할 수 있다.

### P2 — 보고서 완결성과 운영 관찰성

- Target별 미완료·blocked·suspicious·Evidence 누락 종료 점검
- Finding과 Evidence에서 보고서 섹션으로 명시적 연결
- 보고서 export 전 민감정보·깨진 링크·누락 파일 검증
- 도메인 활동 이력을 사람이 읽을 수 있는 감사 화면으로 통합
- 데이터 보존 정책, 진단 bundle과 로그 redaction
- 대용량 출력·Evidence에서 성능 측정 후 필요한 index만 추가

완료 기준:

- 사용자가 평가 종료 시 “무엇을 했고, 무엇을 생략했으며, 어떤 근거로 결론 냈는지”를
  Target별로 확인할 수 있다.
- 내보낸 보고서의 모든 Evidence가 원본과 hash로 추적된다.

### P3 — 선택적 확장

실제 사용 증거가 있을 때만 진행한다.

- 사용자 정의 기본 Runbook package와 서명된 catalog 배포
- pinned MITRE ATT&CK metadata 또는 Atomic Red Team catalog adapter
- 프로젝트 archive/import와 읽기 전용 과거 평가 모드
- PostgreSQL 또는 다중 사용자 배포 검토

다중 사용자로 확장할 경우 인증만 추가해서는 안 된다. Project 격리, secret 관리,
actor가 포함된 감사 이력, 동시 수정 충돌, 실행 권한과 artifact 소유권을 함께 설계해야 한다.

## 명시적 비범위

- 스캔 결과만으로 취약성 또는 성공 여부 판정
- Runbook 자동 적용, Step 자동 완료 또는 command 자동 실행
- 익스플로잇 자동 추천·다운로드·수정·실행
- 자동 Credential spraying, 자동 피벗과 자동 권한 상승
- ARP/DNS/NBNS 스푸핑과 대규모 공격형 스캔
- LLM 기반 공격 계획, 보고서 결론 또는 Finding 자동 생성
- PlexTrac 전체 협업·Purple Team 계층을 그대로 복제하는 작업

## 의사결정 기준

새 기능은 다음 순서로 평가한다.

1. 승인된 평가를 더 재현 가능하게 만드는가?
2. 사용자의 범위·실행·판정 통제를 유지하는가?
3. Observation, Evidence 또는 Execution의 출처가 남는가?
4. 현재 모듈로 해결할 수 있는가, 아니면 새로운 도메인이 정말 필요한가?
5. 자동화가 늘어나는 만큼 preview, 승인, 중단과 감사가 함께 강화되는가?

세 질문 이상을 만족하지 못하면 구현하지 않거나 실험 단계에 둔다.
