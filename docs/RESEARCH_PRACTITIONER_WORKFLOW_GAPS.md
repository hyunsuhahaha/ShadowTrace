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
