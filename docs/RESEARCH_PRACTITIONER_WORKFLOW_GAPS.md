# 공개 현업 평가 흐름과 ShadowTrace 재현 점검

2026-09-26 조사, 2026-09-27 구현 상태 갱신. 앞부분의 빈 구간·우선순위·coverage 표는
당시의 기준선이며 현재 구현 상태는 마지막 절에 정리한다. 이 문서는 공개된 실제 평가
보고서와 방법론을 제품 흐름에 대응시킨다.
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
| 실제 작업 결과와 절차 연결 | Runbook Step에 연결된 Execution·Credential을 Graph 실제 노드와 참조 엣지로 연결. 첨부 Evidence는 민감 제목을 숨긴 Graph 노드로 투영. Observation에서 승격한 Finding도 원래 Step과 연결 | HTTP Exchange·RemoteExecution·InteractiveSession 등 다른 결과 유형과 Step의 직접 링크 없음 |
| 작업 결과와 고객 보고 | Runbook 단계별 판정, Evidence·Execution 연결, 선택형 보고서 coverage | 고객과의 범위 변경·질의·중단 결정을 독립 기록으로 묶는 협업 로그 없음 |

이 네 템플릿은 **수동 판단용 절차**다. 특정 취약점이 있다고 추정하지 않으며,
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

### 평가 유형별 coverage audit

`절차`는 수동 Runbook 단계와 분기, `실행 기록`은 실제 명령·요청·세션과 Evidence,
`자산 모델`은 평가 대상 자체를 정확히 나타낼 수 있는지를 뜻한다. 이 셋을 한 칸에
뭉뚱그려 "지원"이라고 표시하지 않는다.

| 평가 유형 | 절차 | 실행 기록 | 자산 모델 | 확인한 공백 |
|---|---|---|---|---|
| 외부 호스트·서비스 | 20개 서비스 기본 Runbook과 평가 수명주기 | Scan·Execution·Session·Evidence | IP Target·Service | 다중 도메인/조직 범위와 RoE를 강제하지 못함 |
| 내부 네트워크·AD | SMB/LDAP/Kerberos/WinRM 절차, 접근 후 경로 검토 | Credential·RemoteExecution·Tunnel·Directory·Access Lineage | Host/Service/Directory object | 여러 Target을 가로지르는 승인·검사 단계 연계가 없음 |
| 웹 UI | WSTG 12범주 수동 분기 | HTTP 요청/응답, Execution, Finding, Evidence | Service와 URL 요청 | URL·역할·객체별 coverage와 기능 상태 전이를 구조화하지 않음 |
| API | OWASP API Top 10 2023의 10위험 수동 분기 | HTTP 요청/응답, Finding, Evidence | HTTP Service | API 버전·스키마·객체·호출자별 결과 비교 모델 없음 |
| 모바일 앱 | 없음. [Cure53 ODK](https://docs.getodk.org/_downloads/f43f464fe506c2dfea9dad21fac5286b/ODK-Pentest-2024.pdf)는 앱·서버·위협 모델을 별도 작업 패키지로 다룸 | 앱 바이너리·디바이스 런타임 수집 없음 | 앱/빌드/플랫폼 자산 없음 | [MASVS의 8개 통제군](https://mas.owasp.org/MASVS/)을 IP Target에 억지로 넣지 말 것 |
| 퍼블릭 클라우드 | 없음. [CSA Playbook](https://cloudsecurityalliance.org/artifacts/cloud-penetration-testing-playbook) 참조 | 계정/역할/API 호출의 구조화 기록 없음 | 계정·테넌트·리소스 자산 없음 | [AWS 서비스별 허용 범위](https://aws.amazon.com/security/penetration-testing/)와 제공자 RoE를 모델링해야 함 |
| 컨테이너·Kubernetes | 없음. [Kubernetes 보안 체크리스트](https://kubernetes.io/docs/concepts/security/security-checklist/)는 인증/RBAC, 네트워크 정책, Pod 보안 등을 별도 범주로 다룸 | 워크로드/클러스터 상태 기록 없음 | 클러스터·namespace·workload·service account 자산 없음 | Host/Service와 다른 권한·경계 단위가 필요 |
| 소스 코드 리뷰 | [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/assets/OWASP_Code_Review_Guide_v2.pdf)의 위험 기반 코드 분석 절차 없음. Exploit Research에 PoC 작업 기록은 있음 | 코드 변경·분석 근거의 평가 단위 없음 | 저장소·커밋·패키지 자산 없음 | 코드 버전별 Finding/Evidence 고정 필요 |
| 무선 네트워크 | 없음. [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)의 통신·무선 평가 범주와 별도 | 무선 관측/측정 기록 없음 | SSID·BSSID·AP·클라이언트 자산 없음 | 승인된 무선 범위와 물리 위치·시간을 IP Target으로 표현할 수 없음 |
| OT/ICS | 없음. [MITRE ATT&CK ICS](https://attack.mitre.org/matrices/ics/)는 Enterprise와 다른 전술·기술을 정의 | 장비 상태·안전 영향·운영자 승인 기록 없음 | 제어 장비·프로세스·세그먼트 자산 없음 | 운영 안전·가용성 제약을 먼저 모델링해야 하므로 범용 네트워크 절차를 재사용하면 안 됨 |
| 재검증·보고 | Runbook 재검증 단계, Finding retest, 보고서 coverage | Evidence 원본 SHA-256과 Finding 링크 | Project/Target/Service | 보고서의 공격 경로 스냅샷과 고객 의사결정 이력 없음 |

지원하지 않는 평가 유형에 대한 빈 템플릿을 억지로 추가하면 "검사 가능"하다는 잘못된
인상을 줄 수 있다. 다음 기능 작업은 Project RoE와 비-IP 자산 모델을 먼저 정의하고,
실제 결과가 단계·자산·증거에 붙는지 시나리오로 검증해야 한다. 절차 목록만 늘리는
것은 coverage 완료 기준이 아니다.

### 2026-09-26 구현 후 재점검

위 표는 구현 전 조사 기록이다. 현재는 Project RoE 초안·승인·철회·이력과 승인된
기간/행위/대상을 검사하는 실행 가드를 추가했다. 승인 범위는 Graph의 `scope` 노드로
보인다. `web`, `api`, `mobile`, `cloud`, `kubernetes`, `source`, `wireless`, `ics`
AssessmentAsset을 별도 저장하고 Graph의 `asset` 노드에서 Runbook Step, 연결한 Evidence,
승격 Finding까지 탐색할 수 있다. 모바일·클라우드·Kubernetes·소스·무선·ICS에
수동 판단용 절차도 추가했다. 이는 해당 환경에서 명령 실행기나 수집기가 제공된다는
뜻은 아니다. 실제 환경의 원본은 해당 자산에 Evidence로 첨부해 기록한다.

0050–0052 구현 전에 남았던 공백은 다음과 같다.

1. 웹 URL/기능/역할/객체 및 API 버전/스키마/호출자별 coverage 항목의 구조화.
2. RemoteExecution, InteractiveSession의 Runbook Step 직접 참조와
   확인된 다중 Target 작업의 절차 계보. HTTP Exchange는 동일 Target의 Runbook Step에
   직접 연결해 Graph에 기록한다. 현재 Graph의 access lineage는 실제 완료된
   원격 실행을 표현하지만, 별도 Runbook instance들의 단계를 자동으로 이어주지 않는다.
3. 모바일 빌드, 클라우드 계정·역할·리소스, Kubernetes namespace·workload,
   저장소 commit, 무선 BSSID·물리 위치, ICS 장비·운영자 승인 같은 유형별 자산 필드와
   수집 어댑터. 현재 AssessmentAsset의 `details`는 범용 JSON 메타다.
4. 고객 의사결정 기록과 보고서에서 선택한 Graph 공격 경로의 증거 포함 스냅샷.
5. API를 통하지 않고 직접 ORM으로 삽입한 Project에는 RoE 행이 없어 실행 가드가
   건너뛰는 예외. 실제 API 생성 프로젝트와 0048 migration을 거친 기존 프로젝트에는
   초안 행이 존재한다.

따라서 30개 내장 절차가 현업 평가의 모든 경우를 검증한다는 주장은 하지 않는다.
완료 기준은 각 평가 유형에서 실제 작업·부정 결과·증거·Finding이 자산과 Graph
계보에 남고, 승인 범위 밖의 실행이 거부되는지 시나리오로 확인하는 것이다.

### 0050–0053 구현 후 상태

- 같은 Target의 RemoteExecution과 InteractiveSession은 Runbook Step에 직접 연결되고
  Graph에서 실제 기록 노드로 보인다. 여러 Target 사이의 `handoff`는 원본 Step에
  연결한 Credential, 목적 Step에 연결한 완료·exit 0 원격 실행, 해당 실행의 Evidence가
  함께 있을 때만 만든다. 절차 엣지는 공격 성공 경로로 집계하지 않는다.
- Report는 현재 Graph 성공 경로를 선택하고, 연결 Evidence가 있을 때 노드·엣지 상태와
  Evidence SHA-256을 시점별 스냅샷으로 고정한다. Graph를 나중에 수정해도 HTML/PDF/
  DOCX/Markdown 출력의 캡처 내용은 바뀌지 않는다.
- `AssessmentAssetSubject`는 웹 기능·역할·객체, API operation·schema·caller,
  모바일 build, 클라우드 계정·역할·리소스, Kubernetes workload, 소스 commit,
  무선 BSSID·장소, ICS 장비·공정·운영 승인을 유형별 필수 속성과 함께 여러 개 저장하고
  자산 아래 Graph 노드로 투영한다.
- 범위 내 세부 대상을 특정 Runbook Step에 연결하면 `assesses` Graph 엣지가 생기고,
  해당 Step에 붙인 Evidence까지 계보를 따라 확인할 수 있다. 관계만으로 검사를
  성공 처리하지 않는다.
- 자산이 범위 밖이면 세부 대상을 새 Step에 연결할 수 없고, 세부 대상이 있는 자산의
  유형 변경은 거부된다. 보고서에 새 민감 Graph 경로 또는 Evidence를 더하면 기존
  민감도 검토를 다시 해야 한다.

남은 제한은 모바일/클라우드/Kubernetes/
무선/ICS 원본 수집 어댑터, 고객 의사결정 기록, API 밖에서 ORM으로 만든 Project의
RoE 행 누락 예외다. 세부 자산 노드의 존재는 검사를 완료했다는 뜻이 아니다.
