# Architecture

## 제품 원칙

OSCP Workspace는 사용자의 판단을 보조하는 기록·실행 도구다. 시스템은 관찰된 사실,
원본 출력과 사용자가 작성한 메모를 저장하지만 취약 여부나 공격 경로를 판단하지 않는다.
모든 명령 실행은 사용자 선택과 최종 명령 확인을 요구한다.

FastAPI는 비동기 프로세스 실행과 스트리밍 API를 담당하고, React/Vite는 로컬 UI를
제공한다. SQLite는 단일 사용자 데이터를 보존한다. 명령 카탈로그는 YAML로 분리해
코드 변경 없이 검토 가능한 정적 템플릿으로 확장한다.

## 모듈 경계

백엔드 기능은 다음 도메인으로 분리한다. 모듈 간 참조는 정수 ID와 서비스 계층을 통해
이루어지며 다른 모듈의 저장소 구현에 직접 의존하지 않는다.

| 모듈 | 책임 | 자동화 제한 |
|---|---|---|
| `core` | 프로젝트, 대상, 범위, 설정, 감사 이력 | 범위 자동 추론 금지 |
| `scans` | 프로필, 작업 큐, 원본 파일, 파싱, 비교 | 취약점 스캐너/판정 금지 |
| `enumeration` | 서비스 관찰값, 정적 명령 템플릿, 실행 | 공격 명령 자동 선택 금지 |
| `runbooks` | 버전 방법론, 적용 기록, 진행률, Observation과 Finding | 자동 적용·실행·판정 금지 |
| `web` | HTTP 요청 편집, 수동 재전송, 응답 기록 | 자동 공격·퍼징 금지 |
| `directory` | AD 객체와 관계를 사용자가 입력·가져오기 | 공격 경로 자동 판정 금지 |
| `sessions` | 터널과 PTY 세션의 상태 및 수명주기 | 자동 셸 획득 금지 |
| `evidence` | 파일, 스크린샷, 해시, 메모, 연결 | 비밀 평문 로그 금지 |
| `reports` | 사용자가 선택한 증적과 섹션으로 문서 생성 | AI 분석/결론 생성 금지 |

첫 구현은 기존 파일을 유지하지만 신규 기능은 `backend/app/modules/<module>`과
`frontend/src/features/<module>` 아래에 둔다. 공용 타입과 UI 요소만 각각 `core`와
`shared`에서 제공한다.

두 개발 도구 사이의 최신 작업 상태와 다음 단계는 저장소 루트의 `HANDOFF.md`에
짧게 유지한다. 상세 구현 이력은 이 문서가 아니라 `docs/WORKLOG.md`에 누적한다.

## 저장소와 데이터

XDG 규칙을 우선하며 `OSCP_WORKSPACE_*` 환경 변수로 위치를 바꿀 수 있다.

- config: `~/.config/oscp-workspace`
- database: `~/.local/share/oscp-workspace/workspace.db`
- logs: `~/.local/state/oscp-workspace`
- artifacts: `~/OSCP-Workspace/projects/<safe-name>/targets/<safe-ip>/`

기본 관계는 Project 1—N Target 1—N Scan/Service/Execution/Evidence다. 원본 스캔
파일은 불변으로 보존하고 파싱 결과에 원본 ID를 기록한다. HTTP 요청과 응답은 자격증명
필드와 분리하며, 증적은 SHA-256과 취득 시각을 기록한다.

## 현재 API

- `/api/projects`, `/api/targets`: CRUD
- `/api/targets/{id}/nmap`: 크기 제한과 `defusedxml`을 적용한 XML 가져오기
- `/api/targets/{id}/services`: 발견 서비스
- `/api/services/{id}/commands`: YAML 템플릿과 최종 명령 미리보기
- `/api/executions`: 사용자가 확인한 명령 실행
- `/api/executions/{id}/events`: SSE 출력
- `/api/executions/{id}/stop`: 프로세스 그룹 TERM 후 KILL
- `/api/runbooks/templates`: built-in 및 사용자 방법론 Library
- `/api/runbooks/recommendations/{service_id}`: Service 기반 Runbook 추천
- `/api/runbooks/target-recommendations/{target_id}`: Target 범위 Runbook 추천
- `/api/runbooks/instances`: 발행 Version 적용과 수행 Instance 조회
- `/api/system/status`: 설치 도구, `tun0`, route 상태
- `/api/product/capabilities`: UI가 표시할 허용·금지 기능 정책

## 실행 및 보안 경계

- 서버는 `127.0.0.1`에만 바인딩한다. 일반 직접 root 실행은 거부하며 제공된
  loopback 전용 launcher만 제한적으로 허용한다.
- 명령은 shell 문자열이 아니라 `shlex.split`된 argv로 실행한다.
- 서버가 템플릿과 검증된 변수를 다시 렌더링한다.
- 실행 전 최종 명령과 대상, 위험 표시를 확인한다.
- subprocess는 새 process group으로 시작하고 중단 시 자식까지 종료한다.
- sudo 암호와 대화형 세션 인증 입력은 저장하지 않는다.
- Credential Store의 비밀번호 저장은 명시적 opt-in이다. 저장된 값은 로컬 단일
  사용자 SQLite에만 있고 명령 자동채움에만 쓰이며 전역 검색·보고서에는 노출하지
  않는다. 기본값은 힌트만 기록한다.
- 민감 변수는 로그와 출력에서 마스킹한다.
- 경로 구성요소를 allow-list 방식으로 정규화한다.
- 업로드 파일은 크기, 형식, 저장 경로를 검증한다.
- 자동 취약점 판정, 자동 공격 및 스푸핑 기능은 코드 리뷰에서 거부한다.
