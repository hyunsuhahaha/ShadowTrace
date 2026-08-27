# ShadowTrace

승인된 단일 사용자 침투 테스트에서 범위, 관찰, 실행, 증적과 수동 판단을 일관되게
기록하기 위한 제품 언어입니다.

## Assessment Scope

**Project**:
하나의 승인된 평가 작업과 그 데이터를 묶는 최상위 범위입니다.
_Avoid_: Workspace, Engagement

**Target**:
Project 안에서 조사하는 하나의 호스트 또는 IP 기반 대상입니다.
_Avoid_: Asset, Machine

**Service**:
Target에서 관찰된 포트·프로토콜·서비스 정체성입니다. 취약성 또는 공격 가능성을
의미하지 않습니다.
_Avoid_: Endpoint, Vulnerability

## Facts and Decisions

**Raw Activity Event**:
Observer가 endpoint에서 포착한 하나의 process, stdio, socket, filesystem 또는 loss
신호입니다. source, sequence, timestamp, process context, capture state, confidence와
원본 payload를 보존하지만 사용자의 의도나 보안 의미를 단정하지 않습니다.
_Avoid_: Observation, Finding, Execution

**Process Instance**:
하나의 boot 안에서 PID와 kernel process start time으로 구분되는 process incarnation입니다.
PPID, SID, PGID, TTY, namespace/cgroup과 raw evidence 범위를 보존합니다.
_Avoid_: Command, Session, Tool Result

**Terminal Session**:
boot, PID namespace, SID와 controlling TTY/PTY를 이용해 분리한 local terminal 흐름입니다.
tmux pane은 PTY가 다를 때 별도 Session이며 사용자 의도나 pane 이름을 의미하지 않습니다.
_Avoid_: InteractiveSession, Engagement

**Command Activity**:
Process Instance, PGID, stdio FD topology와 PTY evidence를 시간축으로 correlation한 작업
후보입니다. shell input만 있는 경우 실행 사실이 아니라 낮은 confidence의 candidate입니다.
_Avoid_: Execution, Observation, Finding

**Remote Session Candidate**:
로컬 SSH client process와 그 PTY I/O가 원격 대화형 흐름일 가능성을 나타내는 후보입니다.
SSH ciphertext를 해석하거나 원격 명령 실행 성공을 단정하지 않습니다.
_Avoid_: RemoteExecution, Proven Session

**Passive Activity**:
Workspace 밖에서 사용자가 실행한 도구 활동을 여러 Raw Activity Event로부터 묶은
기록입니다. 현재는 Nmap projection에만 사용하며 Workspace가 실행한 것이 아니고
파싱된 사실이나 보안 판정을 의미하지 않습니다.
_Avoid_: Execution, Observation, Audit Event

**Observation**:
스캔이나 수동 조사에서 확인한 사실 또는 추가 검토가 필요한 단서입니다. 그 자체로
취약성 판정은 아닙니다.
_Avoid_: Finding, Issue

**Finding**:
사용자가 Observation을 검토해 별도로 관리하기로 승격한 보안 문제 후보입니다.
_Avoid_: Observation, Alert

**Evidence**:
판단을 재현하거나 보고서 내용을 뒷받침하는 원본 파일, 출력, 스크린샷 또는 메모입니다.
_Avoid_: Artifact

**Execution**:
사용자가 Workspace 안에서 대상과 최종 명령을 확인하고 승인한 한 번의
명령 수행 기록입니다.
_Avoid_: Automation, Job

## Access Lineage

**Credential**:
Target 또는 Service에서 획득하거나 사용자가 기록한 인증 수단입니다. 화면의 계정·유형
표시는 가능하지만 저장된 비밀값 자체는 lineage가 아닙니다.
_Avoid_: Password, Account

**Access Lineage**:
Credential을 어디서 획득했고, 그 Credential로 어느 Target 인증에 성공했는지를 연결한
증거 기반 경로입니다. 추천이나 실패한 인증 시도는 포함하지 않습니다.
_Avoid_: Suggested Path, Possible Attack Path

**Lateral Access**:
한 Target에서 획득한 Credential로 다른 Target 인증에 성공한 관계입니다. 트래픽이 원본
Target을 경유했다는 뜻은 아닙니다.
_Avoid_: Pivot

**Pivot**:
Tunnel이나 프록시처럼 한 Target을 실제 네트워크 경유점으로 사용한 관계입니다.
Credential 재사용만으로 Pivot이라고 부르지 않습니다.
_Avoid_: Lateral Access, Credential Reuse

**Terminal Candidate**:
명령 stdout에서 IP, URL 또는 open Service 형태로 탐지됐지만 아직 사용자가 승인하지 않은
다음 행동 후보입니다. Candidate 자체는 Graph나 Evidence를 변경하지 않습니다.
_Avoid_: Finding, Auto-discovered Node

**Attack Replay**:
append-only Graph Snapshot을 시간순으로 재생하는 읽기 전용 과거 상태입니다. 과거 시점에서
명령 실행이나 Graph 편집은 허용하지 않으며 LIVE로 복귀해야 작업을 계속할 수 있습니다.
_Avoid_: Undo, Rollback

## Runbooks

**Runbook Template**:
Target 또는 Service에 반복 적용할 수 있는 방법론의 논리적 정체성입니다.
_Avoid_: Checklist, Playbook

**Runbook Version**:
특정 시점에 발행되어 더 이상 바뀌지 않는 Template과 ordered Step의 snapshot입니다.
_Avoid_: Draft

**Runbook Instance**:
발행된 Runbook Version을 특정 Target 또는 Service에 적용해 만든 실제 수행 기록입니다.
_Avoid_: Template, Engagement

**Step**:
Runbook 안에서 사용자가 수행 여부와 결과를 직접 판정하는 하나의 조사 단위입니다.
_Avoid_: Command, Task

**Recommendation**:
관찰된 Target 또는 Service 정보와 일치하는 Runbook Version을 설명 가능한 근거와 함께
제안한 것입니다. 적용이나 실행을 뜻하지 않습니다.
_Avoid_: Auto-apply, Auto-run

**Apply**:
사용자가 Runbook Version을 선택해 Instance와 Step snapshot을 생성하는 행위입니다.
명령을 실행하거나 Step을 완료하지 않습니다.
_Avoid_: Execute, Start attack

**Command Reference**:
Step이 정적 명령 카탈로그의 command ID를 가리키는 연결입니다. 실행 권한이나 저장된
명령 문자열이 아닙니다.
_Avoid_: Command, Script
