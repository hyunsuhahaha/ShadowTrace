# 작업 지침

## 기본 원칙

- 사용자가 문제를 제기하면 증상 우회보다 재현 가능한 증거를 수집하고 근본 원인을 먼저 규명한다.
- 진단 요청에서는 원인과 근거를 설명한다. 사용자가 수정을 요청하지 않았다면 파일이나 시스템을 임의로 변경하지 않는다.
- 기존 파일과 사용자 변경사항을 보존하고 요청 범위 밖의 작업은 피한다.
- 작업 적용을 위해 서버 재시작이 필요하면 완료 안내에 재시작이 필요하다고 명시한다.
- 허가된 OffSec 학습 환경, 개인 실습실 또는 명시적으로 승인된 대상만 다룬다.
- 사용자가 "이거 당연히 되어 있어야 하는 거 아니야?"라고 묻거나, 기능이 반쯤만 동작하는
  것을 지적하면 [`docs/OBVIOUSNESS_STANDARD.md`](docs/OBVIOUSNESS_STANDARD.md)의 기준으로
  스스로 감사(audit)한다 — 코드/카탈로그 설명이 약속한 것과 실제 동작이 다른지, 같은
  버그 패턴이 다른 곳에도 있는지, 기존 UX 패턴이 비슷한 다른 곳엔 빠져 있지 않은지 확인하고
  고친다. 사용자가 먼저 지적하기 전에도 비슷한 코드를 만질 때마다 적용한다.
- 이 워크스페이스에서 대상 박스(예: 10.129.x.x)를 다루는 건 이 앱 자체를 개발·검증하기
  위한 수단이지 그 박스를 푸는 게 목적이 아니다. 진단·구현 중 크랙된 비밀번호, 플래그 같은
  박스 관련 결과물을 우연히 얻었다고 해서 "이걸 그래프에 반영할까요?" 같은 1회성·부수적
  제안을 스스로 꺼내지 않는다 — 사용자가 명시적으로 요청한 앱 기능 개발에 집중하고,
  박스 자체에 대한 다음 행동은 사용자가 먼저 요청할 때만 다룬다.
- 사용자가 "OO 박스 풀이에 필요한 기능/흐름을 만들어줘" 처럼 좁은 기능 하나가 아니라
  전체 워크플로우를 요청하면 [`docs/END_TO_END_FLOW_STANDARD.md`](docs/END_TO_END_FLOW_STANDARD.md)의
  기준을 따른다 — 구현 전에 전체 공격 체인을 그래프 노드·화면에 매핑해 끊기는 지점을
  먼저 목록으로 보고하고, 구현 후에는 브라우저로 직접 그 흐름 전체를 재현해 검증한
  뒤에만 완료로 보고한다.

## 코드베이스 탐색

- 파일 위치, 모듈 책임, 프런트엔드 화면 구성, custom event(`oscp-*`)나 localStorage
  키의 의미가 궁금하면 먼저 [`docs/ENGINEERING_ONBOARDING.md`](docs/ENGINEERING_ONBOARDING.md)를
  읽는다 — 백엔드 21개 모듈과 최상위 파일, 프런트엔드 14개 워크스페이스와 하위
  컴포넌트, custom event 5종, localStorage 키, CSS 파일까지 파일 단위로 정리돼 있다.
  이 문서를 먼저 읽고도 부족할 때만 직접 탐색한다.
- 이 문서는 사실 나열용이며 설계 원칙은 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
  도메인 용어는 [`CONTEXT.md`](CONTEXT.md), 현재 세션 상태는
  [`HANDOFF.md`](HANDOFF.md)에 있다. 단, `ARCHITECTURE.md`의 모듈 표는 오래돼 실제
  폴더 구성과 어긋난 부분이 있다(`ENGINEERING_ONBOARDING.md` §11.1에 정리됨) — 모듈
  이름/책임을 확인할 때는 `ENGINEERING_ONBOARDING.md`를 우선한다.
- Progress Graph에 새 도메인 엔티티를 동기화하거나(`sync_from_project`) 그 엔티티를 만드는
  엔드포인트/폼을 건드릴 때는 [`docs/SPEC_GRAPH_TRACKER.md`](docs/SPEC_GRAPH_TRACKER.md)
  §6.1의 "노드 연결 원칙"을 따른다 — 부모는 항상 그 노드가 존재하는 **가장 구체적인 직접
  원인**이어야 하며, 호스트/서비스 부착은 더 구체적인 원인이 없을 때만 쓰는 최후 폴백이다.
  `graph_node_id`를 스키마에 받아 `graph_parent_node_id`로 저장하고 sync가 그 명시적
  부모를 우선하는 패턴(`InteractiveSession`/`HashCrackJob`에 이미 적용됨)을 새 엔티티에도
  같은 방식으로 적용한다.
- 새 파일·모듈·라우트·custom event를 추가하거나 옮기거나 지웠다면
  `docs/ENGINEERING_ONBOARDING.md`의 해당 절도 같은 작업에서 함께 갱신한다. 갱신하지
  않으면 다음 세션이 다시 전수조사를 해야 한다.

## OSCP+ 시험 준수

- 이 에이전트와 ChatGPT, Codex, KAI, DeepSeek, Gemini 등 모든 LLM·AI 챗봇은 실제 시험 진행 및 시험 보고서 작성 단계에서 사용하지 않는다.
- 사용자가 실제 시험 세션, 시험 VPN, 시험 제어판 또는 시험 대상임을 밝히면 즉시 기술적 지원과 명령 실행을 중단하고 최신 OffSec 공식 규정을 안내한다.
- 시험 정보, 대상 정보, 자격 증명, 출력, 스크린샷 또는 증거 파일을 외부 서비스나 다른 사람에게 공유하지 않는다.
- 시험 환경에서 내려받은 애플리케이션, 파일 또는 소스 코드를 로컬로 반출하지 않는다. 단, 대상 침해에 필요한 경우에 한해 공식 가이드가 허용하는 범위에서 사용하고 목표 완료 후 삭제한다.
- 규정은 변경될 수 있다. 허용 여부가 불명확하면 추측하지 말고 최신 OSCP+ Exam Guide와 FAQ를 우선 확인한다.

### 시험에서 금지되는 도구와 기능

- IP, ARP, DNS, NBNS 등의 spoofing 또는 poisoning 기능
- Metasploit Pro, Burp Suite Pro 등 상용 도구·서비스
- `db_autopwn`, `browser_autopwn`, SQLmap, SQLninja 등 자동 익스플로잇 도구 및 동등한 기능
- Nessus, NeXpose, OpenVAS, Canvas, Core Impact, SAINT 등 대규모 취약점 스캐너 및 동등한 기능
- 다른 도구에 포함된 위 금지 기능, 자동화 플러그인, 외부 서비스 또는 래퍼
- Discord, 포럼, 메신저 등에서 시험 관련 힌트나 제3자의 도움을 요청하거나 받는 행위

도구 이름이 목록에 없더라도 같은 금지 기능을 수행하면 사용하지 않는다. 설치 여부가 아니라 실제로 사용하는 기능을 기준으로 판단한다.

### Metasploit 및 Meterpreter 제한

- Metasploit의 Auxiliary, Exploit, Post 모듈과 Meterpreter payload는 선택한 단 하나의 대상 머신에만 사용한다.
- `check`를 포함해 여러 머신에서 시험한 뒤 대상을 고르지 않는다. 한 대상에서 실패해도 다른 대상으로 변경하지 않는다.
- Metasploit을 pivoting에 사용하지 않는다.
- `exploit/multi/handler`와 `msfvenom`은 모든 대상에서 사용할 수 있지만 Meterpreter payload는 여전히 한 대상에만 제한한다.
- Armitage, Cobalt Strike 등 Metasploit을 내부적으로 사용하는 인터페이스에도 동일한 제한을 적용한다.

## Skill 사용

- 버그, 실패 또는 성능 저하 진단: `diagnosing-bugs`
- 코드 작성, 수정 또는 리팩터링: `ponytail`
- 테스트 우선 구현: `tdd`
- 변경사항 또는 브랜치 리뷰: `code-review`
- 모듈 인터페이스와 구조 설계: `codebase-design`
- 최신 OSCP 규정이나 공식 자료 조사: `research`

Skill을 사용할 때는 해당 `SKILL.md`를 먼저 끝까지 읽고 그 지침을 따른다.

## 공식 기준

- OSCP+ Exam Guide: https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide
- OSCP+ Exam FAQ: https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ
- 마지막 확인일: 2026-08-07
