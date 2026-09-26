# 공개 현업 평가 흐름과 ShadowTrace 재현 점검

2026-09-26. 이 문서는 공개된 실제 평가 보고서와 방법론을 제품 흐름에 대응시킨다.
공개 보고서는 평가 대상의 현재 취약성을 주장하는 자료가 아니라, 테스터가 수행한
작업과 보고 방식의 사례로만 사용한다. 재현은 승인된 로컬 실습 데이터에서 한다.

## 수집한 작업 흐름

| 근거 | 현업 작업 흐름 | ShadowTrace 대응 |
|---|---|---|
| [Cure53의 Raspberry Pi 평가 보고서(2025)](https://cure53.de/pentest-report_raspberry-web.pdf), pp. 2–6 | 웹·인증·클라이언트를 작업 범위로 나누고, 코드 검토와 동적 검사를 병행했다. 인증, CSRF, SQLi, 권한 통제 등에서 문제가 발견되지 않은 검사도 `Test Methodology`에 남긴 뒤 취약점과 일반 약점을 별도로 기술했다. | Project/Target과 Runbook Step은 검사 범위와 결과를 기록할 수 있다. Finding/Evidence는 확인한 문제를 기록한다. |
| [CISA의 공개 레드팀 평가(2024)](https://www.cisa.gov/sites/default/files/2024-11/aa24-326a-enhancing-cyber-resilience-insights-from-cisa-red-team-assessment_0.pdf) | 초기 접근, 권한 상승, 자격증명 사용, 측면 이동과 방어 측 탐지를 시간순 공격 경로로 설명한다. 레드팀 평가라 단일 호스트 침투 테스트보다 범위가 넓다. | Graph의 실행·Credential·접근 관계와 Evidence를 이용해 일부 경로를 추적할 수 있다. |
| [PTES Reporting](https://www.pentest-standard.org/index.php/Reporting) 및 [OWASP WSTG Reporting](https://wstg.owasp.org/v4.2/5-Reporting/) | 합의된 범위, 시험 방법, 확인된 문제의 재현·영향·근거, 개선 조치를 독자별 보고서에 담는다. | Finding, Evidence, Retest, client/internal report가 있다. |

## 실제 사용자 순서로 걸어본 결과

1. **범위 확정:** Project와 Target을 만들 수 있다. 승인 기간, 제외 시스템, 허용한
   시험 강도 등 Rules of Engagement는 구조화돼 있지 않고 Project 설명 또는 보고서
   Markdown에 자유 입력해야 한다. **빈 구간 A.**
2. **정찰·검사:** Scan/Execution/Web Testing 결과를 저장하고 Runbook Step에 Evidence와
   Execution을 연결할 수 있다. Step에는 `completed`, `not_found` 같은 수동 판정이 있다.
3. **검사 범위 보고:** 기존 보고서 HTML/PDF/DOCX 렌더러는 Finding, Evidence,
   Exploit Research를 출력하지만 Runbook Step을 읽지 않았다. Cure53 사례처럼 발견한
   문제가 적을 때 어떤 검사를 수행했는지 보고서에서 사라졌다. **빈 구간 B — 이번에
   선택형 Runbook 검사 범위 출력으로 연결.** 원문 결과·메모는 자동 공개하지 않는다.
4. **확인된 문제:** Finding에 재현 절차, 영향, 개선 권고, Evidence를 연결하고 Retest를
   남길 수 있다. 미확인 원시 증거는 자동 Finding으로 승격하지 않는다.
5. **공격 경로 설명:** Graph에는 실행과 접근 관계가 있으나 보고서에는 경로의 시각·근거를
   선택해 고정하는 구조화된 섹션이 없다. CISA 보고서와 비교한 **빈 구간 C.**
6. **고객 공유:** client/internal profile은 있지만 Cure53 사례의 수행 중 질의·상태
   공유와 결정 기록은 Project 단위 기록으로 묶이지 않는다. **빈 구간 D.**

다음 우선순위는 A(범위·허용 조건)와 C(선택한 공격 경로의 보고서 고정)이다. 둘 다
실제 평가의 맥락과 증거를 잘못 전달할 위험이 있어 별도 도메인 설계가 필요하다.

## 2026-09-26 확장 조사: 실제 흐름의 분기와 제품 재현

이전 점검은 보고서 출력에 치우쳤다. 이번에는 공개된 현업 평가 보고서와 방법론의
**작업 순서, 갈림길, 실패·미발견 결과, 후속 조치**를 별도로 비교했다. 단일 문서가
가능한 모든 평가를 열거하지는 않으므로 아래는 제품이 실제 지원하는 범위와 남은
공백의 목록이다. 시험 데이터는 사용하지 않았다.

### 조사 근거

| 자료 | 확인한 흐름 |
|---|---|
| [PTES의 7단계](https://www.pentest-standard.org/index.php/Main_Page), [Pre-engagement](https://www.pentest-standard.org/index.php/Pre-engagement), [Vulnerability Analysis](https://www.pentest-standard.org/index.php/Vulnerability_Analysis) | 범위·허용 조건을 합의하고 정보 수집→위협 가설→검증→영향→보고를 진행한다. 발견한 자산은 범위 재확인이 필요하며 공격 트리를 수행 중 갱신한다. |
| [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) | 평가 계획, 기술 선택, 실행, 결과 분석과 완화 방안의 반복 가능한 기록이 중요하다. |
| [OWASP WSTG v4.2](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/00-Introduction_and_Objectives/) | 기능·입력점 파악 뒤 정보·구성·계정·인증·권한·세션·입력·오류·암호화·업무 로직·클라이언트·API의 12개 범주를 검사한다. |
| [Cure53 Project 11 웹·API 평가](https://cure53.de/pentest-report_project-11-web.pdf), [Cure53 ODK 모바일·서버 평가](https://docs.getodk.org/_downloads/f43f464fe506c2dfea9dad21fac5286b/ODK-Pentest-2024.pdf) | 같은 조직의 평가도 웹 UI·REST API·인프라 또는 모바일 앱·백엔드·위협 모델처럼 작업 패키지가 달라진다. 인증·권한·주입·서버 요청 경계를 실제 기능에 맞춰 검증한다. |
| [CISA 공개 레드팀 평가](https://www.cisa.gov/sites/default/files/2024-11/aa24-326a-enhancing-cyber-resilience-insights-from-cisa-red-team-assessment_0.pdf) | 실패한 초기 접근도 시간축에 남기고, 확인된 접근 이후 권한·자격증명·측면 이동·방어 반응을 근거와 함께 연결한다. |
| [MITRE ATT&CK Enterprise 전술](https://attack.mitre.org/tactics/) | 접근 후 조사·권한·자격증명·측면 이동·수집·영향은 서로 다른 목적이며 성공 추정과 실제 결과를 분리해야 한다. |
| [OWASP API Security Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/) | 객체·속성·기능 권한과 인증 외에도 자원 사용, 업무 흐름, SSRF, 구성, 구버전 API, 외부 API 신뢰를 별도 점검한다. |
| [OWASP MASVS/MASTG](https://mas.owasp.org/MASVS/) | 모바일 앱은 저장소·암호화·인증·네트워크·플랫폼·코드·변조 저항·개인정보 등 IP 기반 웹 대상과 다른 자산/검사 단위를 요구한다. |
| [CSA Cloud Penetration Testing Playbook](https://cloudsecurityalliance.org/artifacts/cloud-penetration-testing-playbook), [AWS 허용 서비스 정책](https://aws.amazon.com/security/penetration-testing/) | 클라우드 평가에는 계정/테넌트와 제공자 허용 서비스의 경계가 필요하다. IP Target으로만 표현하면 승인 범위를 잘못 나타낸다. |

### 흐름별 구현 대조

| 작업 상황 / 갈림길 | 이번 제품 재현 | 남은 공백 |
|---|---|---|
| 범위 승인 전·후, 범위 밖 자산 발견, 영향 검증 허용 여부 | `assessment-lifecycle` Target Runbook 9단계. 승인, 검증 결과에 따른 영향 검증/보고 분기, 재검증·정리 노드 | 승인자의 신원·기간·대상 목록을 강제하는 Project 수준 RoE 구조 없음 |
| 웹 기능·역할·입력점 → 병렬 검사 → 모든 범주 판정 | `web-application-review` HTTP Runbook 14단계. WSTG 12범주 병렬 분기와 `join: all` 근거 검토 | 범주마다 실제 URL·계정·객체를 구조화한 coverage table 없음. 모바일 앱 고유 검사는 미지원 |
| API endpoint·호출자·객체 → 위험별 검사 → 전체 판정 | `api-security-review` HTTP Runbook 12단계. API Top 10 2023을 각각 수동 판정하고 `join: all`로 검토 | API 명세 버전·객체·역할별 결과를 구조화해 비교하는 저장 모델 없음 |
| 확인된 접근 → 권한·Credential·인접 시스템·업무 영향 → 경로 검토·정리 | `post-access-review` Target Runbook 7단계. 후속 검증 승인, 4가지 병렬 검토와 근거 검토 | 접근/자격증명/터널이 서로 다른 Target Runbook 단계로 자동 연결되는 교차 Target workflow edge 없음 |
| 부정 결과·차단·보류·오류·승인 거부 | Runbook `outcome`/`status`/`activation`으로 기록. Graph에 단계 노드와 선언된 전이를 표시하고 `decision_trace`로 실제 선택된 전이를 청록색, 제외된 전이를 점선으로 구별 | 분기 판단 시각과 근거를 Graph 엣지에서 직접 열람하는 기능 없음 |
| 실제 작업 결과와 절차 연결 | Runbook Step에 연결된 Execution·Credential을 Graph 실제 노드와 참조 엣지로 연결. 첨부 Evidence는 민감 제목을 숨긴 Graph 노드로 투영 | HTTP Exchange·RemoteExecution·InteractiveSession 등 다른 결과 유형과 Step의 직접 링크 없음 |
| 작업 결과와 고객 보고 | Runbook 단계별 판정, Evidence·Execution 연결, 선택형 보고서 coverage | 고객과의 범위 변경·질의·중단 결정을 독립 기록으로 묶는 협업 로그 없음 |

이 세 템플릿은 **수동 판단용 절차**다. 특정 취약점이 있다고 추정하지 않으며,
자동 익스플로잇·대규모 취약점 스캔·포이즈닝 기능을 추가하지 않는다. Runbook
단계 완료는 작업 완료일 뿐 침해 성공의 증명이 아니므로 Graph의 공격 성공 경로로
집계하지 않는다. 사용자별 실제 평가 환경에 맞춰 템플릿을 복제·수정할 수 있다.

### 다음 구현 우선순위

1. Project 수준 RoE: 승인 대상·제외 대상·기간·허용 행위·승인 이력의 구조화와 실행 전 확인.
2. Graph에서 선언된 후보 전이와 실제 선택된 전이를 구별하고, 다른 Target의 단계와
   확인된 접근 계보를 증거 기반으로 연결.
3. 웹 기능·계정·객체별 coverage, 모바일·클라우드·무선·소스 리뷰 등의 별도 자산/절차
   유형. IP 기반 Target 한 종류에 억지로 담지 않는다.
4. 확인된 공격 경로의 특정 스냅샷과 연결 Evidence를 보고서에 고정.
