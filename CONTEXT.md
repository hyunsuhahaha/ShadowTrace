# OSCP Workspace

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
사용자가 대상과 최종 명령을 확인하고 승인한 한 번의 명령 수행 기록입니다.
_Avoid_: Automation, Job

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
