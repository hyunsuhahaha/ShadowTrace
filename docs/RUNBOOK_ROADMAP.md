# Runbook Direction

기준일: 2026-07-30

## 역할

Runbook은 자동 공격 엔진이 아니라 Target과 Service에 방법론을 적용하고 수행 사실을
남기는 기록 계층이다. `Recommendation → Apply → Execute → Judge`는 각각 별도 사용자
결정이다.

## 현재 구현

- Template, 불변 Version, ordered Step
- Target 또는 Service 범위의 Instance와 Step snapshot
- 18개 built-in Runbook의 idempotent 설치와 stable key
- 서비스명·포트 추천, 적용 상태, fingerprint 기반 숨기기
- built-in 읽기 전용 정책과 사용자 소유 clone
- 사용자 Template 작성·발행·archive, JSON import/export
- 수동 상태와 필수 사유, 결과·메모, 조건부 Step
- Step timer, Target 진행률과 activity timeline
- Execution, Evidence, Credential 연결
- Observation 기록, Finding 승격·상태 변경·Markdown export

적용은 Instance만 생성한다. 명령 실행은 Service Enumeration의 preview와 일회성 승인을
거쳐야 하며 exit code도 Step 완료나 Finding 확정으로 자동 변환되지 않는다.

## 다음 구현 순서

### 1. 기본 콘텐츠 신뢰성

- Database, Mail, LDAP/Kerberos와 RDP/WinRM을 제품별 Template로 세분화
- command reference 유일성·존재·coverage CI 검사
- provenance, content hash, source version과 installed-at 저장
- built-in 업데이트 전 Step/command diff 제공
- 삭제된 command reference의 과거 표시와 실행 차단

### 2. 추천 품질

- service name exact match와 port-only match의 신뢰도 구분
- service/port 충돌 시 Unknown Service 식별 Runbook 함께 제안
- 적용 전 전체 Step과 command risk 요약
- 추천 숨김 복원과 적용 Version 교체 흐름
- Scan/Service fingerprint 변경 시 설명 가능한 재추천

### 3. 수행·보고 연결

- Service Enumeration과 Runbook Step 사이의 양방향 이동
- 새 Credential 등록 시 관련 Service 재확인 inbox
- Finding에 영향·재현·완화와 Evidence 연결 추가
- 평가 종료 전 미완료, skip 사유, blocked, suspicious와 Evidence 누락 점검
- Target별 Runbook 수행 내역을 보고서에 선택적으로 포함

## 유지할 계약

- Template 변경은 기존 Version과 Instance를 바꾸지 않는다.
- built-in은 edit/archive/delete하지 않고 clone하여 수정한다.
- 추천은 자동 적용되지 않는다.
- Apply는 실행하지 않는다.
- 실행 성공은 Step 완료가 아니다.
- Observation은 Finding이 아니다.
- Credential에는 평문 secret을 저장하지 않는다.
- 모든 command는 현재 catalog에서 다시 검증하고 사용자가 승인한다.

## 비범위

- 임의 코드 조건식
- AI가 생성한 공격 절차나 자동 판단
- Runbook이 직접 command API를 호출하는 자율 실행
- PlexTrac의 RBAC·협업·Purple Team 전체 계층 복제
- MITRE ATT&CK 또는 Atomic Red Team 콘텐츠의 무분별한 자동 실행

공식 제품 및 지식 원천 비교와 상세 근거는
[RUNBOOK_PRODUCT_RESEARCH.md](./RUNBOOK_PRODUCT_RESEARCH.md)를 참고한다.
