# Research: OSCP/OSCP+ 실전 시험에서 자체 제작 웹 대시보드/그래프형 진행 추적 도구를 쓴 선례가 있는가

**목적:** 이 저장소(`oscp-workspace`) 자체가 PTY 세션·리버스 셸·해시크랙 잡·"progress graph"를
추적하는 자체 제작 웹 대시보드다. 관리자가 "이런 걸 만들어서 실제 시험에 쓰는 게 현실적으로
말이 되냐"는 회의를 제기했고, 그 질문에 근거로 답하기 위한 조사다. 이 문서는 이 앱의
합격 가능성을 보장하지 않으며, "선례가 있는가"와 "규정상 문제가 되는가"라는 두 개의 별개
질문에 대해 찾을 수 있는 데까지 찾은 증거를 정리한다.

**Scope of sources:** 1차 자료 우선 — OffSec 공식 Help Center(`help.offsec.com`)의 OSCP+ Exam
Guide, Exam FAQ, Proctored Exam Requirements FAQ, AI Usage Policy, Candidate Handbook을
Zendesk Help Center API(`/api/v2/help_center/en-us/articles/<id>.json`)를 통해 전문(全文)
원문으로 확보했다 — 일반 브라우저 URL은 Cloudflare 계열 봇 차단(HTTP 403, "Enable
JavaScript and cookies")에 걸려 직접 열람이 안 됐지만, 같은 문서를 서빙하는 공개 JSON API
엔드포인트는 열람 가능했다. 모든 원문 인용은 이 API 응답에서 가져온 것이며, 조사 시점은
2026-08-15다. 2차 자료(블로그, GitHub 저장소 README, 커뮤니티 포럼)는 그렇게 명시했다.

**한계 고지 (중요):** 이 세션의 웹 도구는 `reddit.com` 도메인을 크롤링/직접 열람할 수
없었다 (`WebSearch`의 `allowed_domains` 필터가 reddit.com을 거부했고, `WebFetch`도
"unable to fetch from www.reddit.com" 오류를 반환했다). 따라서 r/oscp 스레드 전수 검색은
하지 못했고, 검색엔진이 색인한 reddit 관련 텍스트 스니펫에만 의존했다. r/oscp에 관련 사례가
실제로 존재하더라도 이 조사에서 놓쳤을 가능성이 있다 — 이는 "못 찾았다"를 "존재하지 않는다"로
과잉해석하면 안 되는 이유다.

**Verification legend:** [V] = 원문 그대로/직접 확인된 사실; [I] = 원문에서 도출한 추론
(원문에 문장 그대로는 없음); [D] = 조사 중 스스로 정정한 지점.

---

## 결론 먼저 (Bottom line)

**"실제로 이런 도구를 만들어 시험에 합격한 사례가 있는가?"**
→ **명확한 공개 사례를 찾지 못했다.** 가장 근접한 사례(§2.3의 PentestCompanion)조차 "이
도구로 실제 채점 시험에 합격했다"는 저자 본인의 명시적 진술이 없다. OSCP 커뮤니티에서
공개적으로 확인되는 시험 당일 노트 도구는 거의 전부 Obsidian, CherryTree, Notion 같은
범용 도구이고, 자체 제작 웹 대시보드/그래프 도구는 "준비 단계에서 만들었다"는 사례는
있어도 "시험 당일 그것으로 합격했다"는 1차 증언은 발견되지 않았다. 이 공백은 증거
부재(evidence of absence)가 아니라 자료 부재(absence of evidence)로 읽어야 한다 — §5 참고.

**"규정상 문제가 되는가?"**
→ **공식 문서 어디에도 자체 제작 추적/노트 도구를 금지하는 조항이 없다.** Exam Guide의
"Exam Restrictions"는 정확히 5개 카테고리(스푸핑/상용 도구/자동 익스플로잇/대량 취약점
스캐너/AI 챗봇)만 금지하며, 이 앱처럼 호스트·서비스·세션을 추적만 하는 웹 대시보드는 그
어느 카테고리에도 해당하지 않는다 [V, §3.1]. 오히려 AI Usage Policy는 "Notion 같은
조직화·요약을 돕는 AI 내장 도구는 끄지 않아도 된다"고 명시해, "정리/추적" 범주와
"자동 익스플로잇/챗봇" 범주를 OffSec 스스로 구분하고 있다 [V, §3.3]. 네트워크 격리
규정(오직 시험 VPN에만 연결)은 로컬호스트(127.0.0.1)에서만 통신하는 앱에는 애초에 적용될
여지가 없다 [I, §4]. 유일한 실무 제약은 금지 카테고리가 아니라 **감독관에게 화면과 실행
중인 모든 프로그램을 공유해야 한다**는 절차적 요건이다 [V, §4].

---

## 1. 질문 1 — "자체 제작 도구를 실제 시험에서 썼고 합격했다"는 문서화된 사례가 있는가

### 1.1 검색 방법과 한계

`WebSearch`/`WebFetch`로 다음을 시도했다: (a) "OSCP" + "built my own tool/dashboard/tracker"
류의 블로그·Medium·Reddit 문구 조합 검색, (b) GitHub 검색으로 "OSCP" + "used during my
exam"/"dashboard" 조합, (c) `reddit.com` 도메인 제한 검색(위 한계 고지대로 차단됨), (d)
"OSCP 후기"(my OSCP journey / OSCP review 2024/2025) 계열 블로그 글에서 도구 언급 여부.

### 1.2 찾은 것: 준비용(prep) 자체 제작 도구는 흔하지만, "시험 당일 사용"을 명시한 것은 못 찾음

GitHub에는 `oscp-tools`, `oscp-notes`, `oscp-prep` 토픽 아래 수백 개의 저장소가 있지만
[V, 검색 결과 직접 확인], 그 절대다수는:
- Obsidian/Notion 볼트, CherryTree 파일, 마크다운 노트 모음 (자체 "앱"이 아니라 범용 노트
  포맷 위에 얹은 템플릿), 또는
- 준비 단계 스크립트/치트시트(리버스셸 원라이너 모음, privesc 체크 스크립트 등)

였고, "이 웹 대시보드/그래프 도구로 시험 당일 진행 상황을 추적해서 합격했다"는 형태의
자체 제작 **웹 앱**은 검색으로 표면화되지 않았다. [I]

### 1.3 가장 근접한 사례: Poellie01의 두 저장소 (prep 도구 vs 자체 제작 웹 대시보드의 대조 사례)

같은 GitHub 사용자(`Poellie01`)가 성격이 다른 두 저장소를 공개하고 있어, 사용자가 원한
"prep용으로만 만든 것"과 "시험에 실제로 쓴 것"의 구분을 보여주는 좋은 예시다.

- **`github.com/Poellie01/OSCP-Notes`** — README가 명시적으로 "Obsidian Notes **used to
  pass the OSCP exam** and most HTB machines / challenges."라고 쓰고 있다 [V,
  `https://github.com/Poellie01/OSCP-Notes`]. 즉 실제 합격에 쓰인 도구라고 저자가
  직접 밝혔지만, 이건 Obsidian(범용 노트 앱) 위의 노트 볼트이지 이 저장소 저자가 직접
  코딩한 웹 대시보드/그래프 앱이 아니다 — 사용자가 조사 범위에서 명시적으로 제외한
  "Obsidian/CherryTree/범용 노트 앱" 카테고리에 해당한다.
- **`github.com/Poellie01/PentestCompanion`** — 같은 저자가 만든, 훨씬 야심찬 별도
  프로젝트. README에 따르면 Docker/Python으로 배포하는 **셀프호스팅 웹 대시보드**로,
  Cytoscape 기반 "visual exploitation map"(그래프 시각화), 도구 UI 실행, 자동 findings
  임포트, 그리고 **OSCP를 포함한 자격증별 "exam mode"**(내비게이션 바의 실시간 카운트다운
  타이머, 머신별 포인트 트래커, 스크린샷 슬롯, DOCX/PDF 리포트 생성)를 갖추고 있다 [V,
  `https://github.com/Poellie01/PentestCompanion`]. 이건 정확히 이 워크스페이스가 만들고
  있는 것과 같은 종류의 도구(그래프 기반, 셀프호스팅, 시험 특화 UI)다.
  - **그러나** README 어디에도 "내가 실제 채점 시험에서 이 도구를 켜놓고 썼고 합격했다"는
    저자 본인의 진술이 없다 [V, 부재 확인]. exam mode 기능이 "이 용도로 쓰라고 설계됨"을
    보여줄 뿐, "실제로 그렇게 써서 합격했다"는 증언과는 다르다. `OSCP-Notes` 저장소의
    "used to pass" 문구가 Obsidian을 가리키고 PentestCompanion을 가리키지 않는다는 점도
    이 두 프로젝트가 시간상 별개(아마 합격 후에 더 범용적인 도구로 확장)일 가능성을
    시사한다. [I]

### 1.4 소결

"자체 제작 웹 대시보드/그래프 도구를 실제 채점 시험(graded exam)에서 켜놓고 썼고, 그걸로
합격했다"를 1차 증언 수준으로 명시한 공개 사례는 이번 조사에서 **찾지 못했다**. 가장
근접한 것은 PentestCompanion인데, 이마저 저자의 명시적 "exam-day 사용" 진술이 없어
"prep 단계에서 만들었고 exam mode 기능을 넣어놨다"와 "실제로 그걸로 합격했다" 사이의
간극을 메우지 못한다. §5에서 이 공백을 어떻게 해석해야 하는지 정리한다.

---

## 2. 질문 2 — 공식 Exam Guide/FAQ가 "순수 추적/노트용" 자체 제작 도구에 대해 뭐라고 하는가

### 2.1 Exam Guide의 "Exam Restrictions" 절 전문 (원문)

`https://help.offsec.com/api/v2/help_center/en-us/articles/360040165632.json`의 `body`
필드에서 가져온 원문이다 [V]:

> You cannot use any of the following on the exam:
> - Spoofing (IP, ARP, DNS, NBNS, etc)
> - Commercial tools or services (Metasploit Pro, Burp Pro, etc.)
> - Automatic exploitation tools (e.g. db_autopwn, browser_autopwn, SQLmap, SQLninja etc.)
> - Mass vulnerability scanners (e.g. Nessus, NeXpose, OpenVAS, Canvas, Core Impact, SAINT, etc.)
> - AI Chatbots (OffSec KAI, ChatGPT, YouChat, etc.)
> - Features in other tools that utilize either forbidden or restricted exam limitations
>
> You are not required to disable tools with built-in AI features like Notion or Google AI
> Overview. However, using LLMs and AI chatbots (OffSec KAI, ChatGPT, Deepseek, Gemini, etc.)
> is strictly prohibited. [...] Any tools that perform similar functions as those above are
> also prohibited. You are ultimately responsible for knowing what features or external
> utilities any chosen tool is using. **The primary objective of the OSCP+ exam is to evaluate
> your skills in identifying and exploiting vulnerabilities, not in automating the process.**

정확히 이 6개 항목(5개 불릿 + 캐치올 문장)만 금지 대상이다. "노트 도구", "추적 도구",
"자체 제작 소프트웨어 일반"에 대한 언급은 **전혀 없다**. [V]

### 2.2 FAQ의 허용 도구 목록과 "open book" 조항

`https://help.offsec.com/api/v2/help_center/en-us/articles/4412170923924.json`에서
가져온 원문 [V]:

> All tools that do not perform any restricted actions are allowed during the exam. The
> following tools are allowed, but the list is not limited to these: BloodHound (Legacy and
> Community Edition only), SharpHound, PowerShell Empire, Covenant, Powerview, Rubeus,
> evil-winrm, Responder (Poisoning and Spoofing is not allowed in the challenges or on the
> exam), Crackmapexec, Mimikatz, Impacket, PrintSpoofer.

같은 문서, "Which resources I can use during my active exam?" 절 [V]:

> OSCP+ exam is an open book exam, meaning you are permitted to use your notes, online
> resources (Except for AI chatbots and LLMs with direct prompt access), the OffSec Learning
> Platform, and similar materials. However, all your activities must be conducted on the host
> machine where the proctoring application is running, as the proctor will monitor your
> session.

이 시험이 "open book"이고 "your notes"를 명시적으로 허용한다는 것, 그리고 "the list is not
limited to these"라는 비배타적 허용 원칙이 이미 §2.1과 결합하면: 자체 제작 추적 도구는
"restricted actions"를 수행하지 않는 한(=5개 카테고리에 해당하지 않는 한) 이 개방형 허용
원칙 아래 들어간다. [I] `RESEARCH_TOOL_CATALOG_EXAM_COMPLIANCE.md` §1이 이미 이 저장소의
다른 조사에서 같은 결론(비배타적 allow-list, 실제 테스트는 5개 카테고리 여부)에 도달한 바
있다.

### 2.3 AI Usage Policy — "정리/추적을 돕는 도구"와 "AI 챗봇"을 OffSec 스스로 구분

`https://help.offsec.com/api/v2/help_center/en-us/articles/35549468971156.json` 전문
[V]:

> While you are not required to disable AI-enhanced applications such as Notion, Google AI
> Overview, or similar tools that assist with organization or summarization, there are
> restrictions on the use of AI chatbots and Large Language Models (LLMs) [...]
>
> **Allowed AI Usage:** AI tools that function without prompts for direct assistance or are
> not interactive (e.g., Notion's AI for note organization or Google AI Overview for search
> enhancements) are permitted as long as they are used in accordance with academic policies
> and do not facilitate unauthorized assistance on exams.

이 문서는 정확히 이 조사 질문(정리/추적용 도구 vs 자동화·챗봇용 도구)에 대한 OffSec의
공식 구분선이다. Notion의 "조직화를 돕는" 기능이 명시적으로 허용된다는 것은, 이 워크스페이스
앱처럼 세션/호스트/파인딩을 정리·추적만 하고 프롬프트로 문제를 대신 풀어주지 않는 도구가
같은 논리로 허용 범주에 속한다는 강한 근거다. [I] (참고: 이 앱 자체는 애초에 AI 기능이
없으므로 이 정책은 방증일 뿐, 직접 규율 대상은 아니다.)

### 2.4 Proctored Exam Requirements — 물리적 허용 품목과 "실행 중인 프로그램 공유" 요건

`https://help.offsec.com/api/v2/help_center/en-us/articles/15295546432148.json`에서,
"What are the items that are permitted and prohibited in my exam environment?" 절 원문
[V]:

> You are only allowed to have the host machine and external screens that are shared with
> the Proctoring tool session, as well as printed books, notes, paper, and pen. [...] You are
> not allowed to use any other machine apart from your host, and there should be no other
> electronic devices within your exam area.

이건 **물리적 반입 품목**(호스트 머신 1대, 공유되는 외부 모니터, 종이책/노트/펜) 규정이지,
호스트 머신 안에서 무슨 소프트웨어를 실행할 수 있는지에 대한 화이트리스트가 아니다. [I]
소프트웨어 쪽 통제는 별도 절, "What are the pre-exam requirements the proctor must
verify..." 에 있다 [V]:

> Asking you to scan your room and surroundings with your webcam; **share all your screens
> and display all running programs**; and connect to the exam VPN.

즉 소프트웨어에 대한 규칙은 "무엇을 실행할 수 있는가"가 아니라 "실행 중인 모든 프로그램을
감독관에게 보여줘야 한다"는 **공개(disclosure) 의무**다. 자체 제작 웹 대시보드를 브라우저
탭으로 띄워놓고 쓰는 것 자체를 금지하는 조항은 어디에도 없다 — 다만 그 창도 화면 공유
범위 안에 있어야 한다. [I]

---

## 3. 질문 3 — 같은 영역의 공개 오픈소스 프로젝트 중 "실제 시험에 썼다"고 밝힌 것이 있는가

사용자가 예시로 든 Sirius, Legion, Reconmap, Ghostwriter, Sn1per 대시보드, "traceon"에
대해 개별 검색했다:

- **Ghostwriter** (SpecterOps) — 프로젝트/리포팅 엔진으로 잘 알려져 있으나, 검색으로는
  "OSCP 실제 시험에서 사용했다"는 진술을 찾지 못했다. LinkedIn에 "Johnathan Kuskos, OSCP"가
  Ghostwriter 관련 글을 공유한 게시물이 있었지만 [V, 존재만 확인,
  `linkedin.com/posts/kuskos_...`], 본인이 OSCP 시험 중 Ghostwriter를 썼다는 내용은 아니고
  자격 보유자가 Ghostwriter 관련 콘텐츠를 공유한 것뿐이었다.
- **Reconmap** — 검색 결과에 "pentest report collection/템플릿"으로만 나타났고 OSCP 시험
  사용 관련 언급은 찾지 못했다.
- **Sirius, Legion, Sn1per 대시보드** — 이번 검색에서 유의미한 OSCP 관련 언급을 찾지 못했다.
- **"traceon"** — 사용자가 예시로 든 이름과 일치하는 pentest 추적 프로젝트를 찾지 못했다.
  검색된 동명 프로젝트("Traceon")는 전자현미경 시뮬레이션용 물리 라이브러리로 무관하다. [V]
- **PentestCompanion** (`github.com/Poellie01/PentestCompanion`) — §1.3 참고. 이 영역에서
  가장 근접하지만, "실제 시험에 썼다"는 확증은 없다.
- **APTRS** (`github.com/APTRS/APTRS`) — "Automated pentest reporting with custom
  templates, project tracking, customer dashboard"라고 자기소개하는 셀프호스팅 대시보드형
  프로젝트를 검색 중 발견했으나 [V, 검색 결과 설명], OSCP 특화 기능이나 OSCP 시험 사용
  주장은 없다 — 일반적인 상업 pentest 참여(engagement) 관리 도구에 가깝다.
- **Cervantes, Hexway Hive** — 검색 중 곁가지로 발견된 협업형 pentest 플랫폼들. 둘 다
  OSCP 시험 사용을 주장하지 않으며, 팀 단위 유료/기업용 워크플로우에 가깝다.

### 소결
사용자가 예로 든 프로젝트군 중, "그래프/대시보드형이고 OSCP 시험 사용을 자처하는" 것에
가장 가까운 건 PentestCompanion 하나뿐이었고, 그마저 §1.3에서 정리한 대로 "exam-day 사용"
확증은 없다. 나머지는 인접 카테고리(범용 pentest 참여 관리, 팀 협업 리포팅 툴)이지 "이걸로
OSCP 봤다"는 서사를 갖고 있지 않다.

---

## 4. 질문 4 — 로컬 셀프호스팅 웹 앱이 시험 규정과 충돌할 수 있는가

§2에서 확보한 원문을 종합하면, 잠재적 충돌 지점은 세 갈래로 나뉘고 각각 답이 있다.

### 4.1 "자동 익스플로잇 도구" 카테고리와의 혼동 가능성 — 해당 없음

Exam Guide는 "자동 익스플로잇"과 "대량 취약점 스캐너"를 명시적으로 SQLmap/db_autopwn/
Nessus/OpenVAS류로 예시하며, 공통점은 **익스플로잇 성공 여부를 자동으로 판정하고 다음
단계로 자동 진행**하는 것이다 [V, §2.1]. 이 워크스페이스 앱처럼 사람이 실행한 명령의
결과를 기록·시각화만 하고 익스플로잇 자체를 자동 판단/자동 실행하지 않는 도구는 이
카테고리의 정의에 들지 않는다. [I] (참고: 이 앱의 개별 도구 카탈로그 자체의 5개 카테고리
감사는 별도 문서 `RESEARCH_TOOL_CATALOG_EXAM_COMPLIANCE.md`에서 이미 수행됨 — 이 문서는
"추적/그래프 UI 계층" 자체를 다룬다.)

### 4.2 감독(proctoring)/화면 녹화 규정과의 충돌 가능성 — 절차적 요건일 뿐, 금지 아님

- 화면 녹화는 명시적으로 금지된다: "We do not allow learners to video record their
  screen/s while interacting with any of our exam machines." [V, §2.4] — 그러나 이건
  "시험 머신과 상호작용하는 화면을 녹화해서 저장/유출"하는 행위를 금지하는 것이지, 진행
  상황을 실시간으로 추적하는 로컬 웹 대시보드를 띄워놓는 것과는 다른 층위다. [I] 다만
  이 앱이 PTY 세션 로그를 저장하는 기능이 있다면(`docs/ENGINEERING_ONBOARDING.md` 확인
  필요 — 이 조사에서 코드까지 감사하지는 않았다), "화면 녹화"가 아니라 "터미널 텍스트
  로그 보관"이라는 점에서 원문이 금지하는 대상(영상 녹화, IP 유출 우려)과는 성격이
  다르지만, 감독관에게 설명 가능해야 하는 회색지대로 남는다. [I]
- "실행 중인 모든 프로그램을 공유"해야 한다는 요건(§2.4)은 이 앱이 브라우저 탭으로
  떠 있어도 문제없이 충족 가능하다 — 다른 백그라운드 앱과 마찬가지로 화면 공유 범위
  안에 있으면 된다. [I]

### 4.3 네트워크 격리("오직 시험 VPN에만 연결") 규정과의 충돌 가능성 — 로컬호스트는 애초에 무관

감독관이 확인하는 것은 "you are only connected to the exam VPN" [V, §2.4의 pre-exam
requirements 절] — 이는 **머신이 시험 VPN 외의 다른 네트워크에 동시 접속해 있지 않은가**를
확인하는 절차다. 동시에 FAQ는 "online resources"를 오픈북 자료로 명시 허용하므로 [V,
§2.2], 시험 VPN 외의 일반 인터넷 접속 자체가 전면 금지는 아니라는 것도 원문에서 함께
확인된다 — 다만 "다른 사람에게 힌트를 구하는 행위"는 별도로 금지된다(Discord 조항,
§2.1 근처의 "under no circumstances are you permitted to seek or receive assistance
from others").

이 워크스페이스 앱처럼 **호스트 머신 자기 자신 안에서 127.0.0.1로만 통신하는 로컬
웹서버**는 애초에 "네트워크 접속"이 아니다 — OS 바깥으로 패킷이 나가지 않는다. VPN 규정도
FAQ의 온라인 자료 허용 조항도 둘 다 "그 머신이 어디에 네트워크로 연결돼 있는가"를 다루는
것이지 "그 머신 안에서 어떤 로컬 프로세스를 실행하는가"를 다루지 않으므로, 로컬호스트
전용 앱은 이 규정의 적용 대상 자체가 아니다. [I] 이 결론은 원문에 명시된 문장이 아니라,
VPN-only 규정과 "online resources 허용" 규정이 공존하려면 "네트워크 연결 여부"와
"로컬 프로세스 실행 여부"가 서로 다른 축이어야 한다는 논리적 추론이다.

### 4.4 종합

세 갈래 모두 이 앱과 같은 "순수 추적/시각화용 로컬 웹 대시보드"를 금지하는 근거가 되지
않는다. 유일하게 실무적으로 챙겨야 할 것은 절차적 요건(감독관에게 화면 공유 시 이 앱의
브라우저 탭도 노출됨을 인지하고 있을 것, 자동 익스플로잇으로 오인될 만한 기능은 넣지
않을 것)이지, "허용되는 소프트웨어 카테고리" 목록에 들어있지 않아서 문제가 되는 구조가
아니다. [I]

---

## 5. 왜 1차 증거가 얇은가 — 얇음을 어떻게 해석해야 하는가

이 조사 결과를 "선례가 없다 = 위험하다/비정상이다"로 읽으면 과잉 해석이다. 다음과 같은
합리적 이유들이 "찾지 못함"을 설명한다 [I, 전부 추론]:

1. **표본 자체가 극히 작다.** "OSCP 시험 당일 무슨 소프트웨어를 켜놓고 있었는지"까지
   블로그에 상세히 적는 사람 자체가 드물다. 대부분의 후기는 방법론·시행착오·시험 전략에
   초점을 맞추지, 사용한 노트 도구의 브랜드/자체 개발 여부까지 파고들지 않는다.
2. **Reddit 크롤링이 이 세션에서 막혔다** (앞선 한계 고지 참고) — r/oscp는 이런 종류의
   개인적 팁 공유가 가장 활발할 법한 채널인데 여기 접근이 안 됐다는 것 자체가 조사의
   구조적 공백이다.
3. **"자체 제작 앱을 만들었다"와 "그걸로 시험을 봤다"를 굳이 GitHub README에 함께 적을
   유인이 적다** — Poellie01의 사례(§1.3)처럼 준비 단계 도구와 이후에 확장한 범용 도구가
   분리되어 공개되는 경우, 정확히 "이 특정 버전으로 이 특정 시험을 봤다"는 타임스탬프
   수준의 진술은 애초에 드물게 남는다.
4. 반대로 **금지되어서 못 쓴다는 진술도 찾지 못했다** — 즉 "다들 이걸 시도했다가 규정
   위반으로 걸렸다"는 반증도 없다. 이 침묵은 양방향이다.

**실무적 결론:** "합법이다/불법이다"를 가를 근거는 §2~4의 1차 문서에 이미 충분히 있다
(추적용 도구는 5개 금지 카테고리 어디에도 안 걸림). "남들도 이렇게 했다"는 사회적 증거는
확보하지 못했을 뿐이며, 이건 별개의 질문이다. 이 앱을 실제 시험에서 쓸지 결정할 때
가장 확실한 방법은 OffSec 공식 문서를 근거로 삼되(§2), 애매한 지점(§4.2의 세션 로그 보관
같은 회색지대)은 시험 전 `challenges@offsec.com`에 직접 문의하는 것이다 — Exam Guide
자체가 "we will not comment on allowed or restricted tools, other than what is included
inside this exam guide"라고 명시하므로 [V, §2.1 인용문 근처], 문의해도 도구 이름을 콕
집어 답해주지는 않겠지만 절차적 요건(화면 공유 범위, 녹화 여부 등) 확인에는 유효하다.

---

## 6. 참고 문헌 (References)

**1차 자료 (OffSec 공식, Zendesk Help Center API로 원문 확보):**
- OSCP+ Exam Guide — `https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide`
  (API: `https://help.offsec.com/api/v2/help_center/en-us/articles/360040165632.json`)
- OSCP+ Exam FAQ — `https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ`
  (API: `https://help.offsec.com/api/v2/help_center/en-us/articles/4412170923924.json`)
- Proctored Exam Requirements FAQ —
  `https://help.offsec.com/hc/en-us/articles/15295546432148-Proctored-Exam-Requirements-FAQ`
  (API: `https://help.offsec.com/api/v2/help_center/en-us/articles/15295546432148.json`)
- AI Usage Policy in OffSec Exams —
  `https://help.offsec.com/hc/en-us/articles/35549468971156-AI-Usage-Policy-in-OffSec-Exams`
  (API: `https://help.offsec.com/api/v2/help_center/en-us/articles/35549468971156.json`)
- OSCP+ Candidate Handbook —
  `https://help.offsec.com/hc/en-us/articles/40393367449108-OSCP-Candidate-Handbook`
  (API: `https://help.offsec.com/api/v2/help_center/en-us/articles/40393367449108.json`;
  본문은 다른 문서로의 목차/링크 모음이라 내용은 위 4개 문서에서 확보)

**2차 자료 (커뮤니티/저자 진술, 명시적으로 2차로 표기):**
- `https://github.com/Poellie01/OSCP-Notes` — "Obsidian Notes used to passed the OSCP exam"
- `https://github.com/Poellie01/PentestCompanion` — 셀프호스팅 그래프형 pentest
  대시보드, OSCP 포함 자격증별 exam mode 보유. exam-day 사용 확증 없음.
- `https://github.com/APTRS/APTRS` — 일반 pentest 리포팅/추적 대시보드, OSCP 특화 아님.

**이 저장소 내 관련 선행 조사 (교차 참조):**
- `RESEARCH_TOOL_CATALOG_EXAM_COMPLIANCE.md` — 이 앱이 카탈로그화하는 개별 외부 도구
  (nmap, impacket 등)에 대한 5개 금지 카테고리 감사. 이 문서(추적/그래프 UI 계층)와
  상호 보완적이다.
- `RESEARCH_DOTDOTPWN_EXAM_COMPLIANCE.md` — 5개 금지 카테고리 원문의 최초 인용처.

---

## 7. 이 문서의 한계 (재확인)

- OffSec은 "we will not comment on allowed or restricted tools, other than what is
  included inside this exam guide"라고 명시하므로 [V], 이 문서의 §2~4 결론은 전부
  공개된 원문에 대한 **해석**이지 OffSec의 공식 유권해석이 아니다.
- Reddit 직접 크롤링 실패로 r/oscp 1차 스레드 전수조사는 못 했다 (§0 한계 고지).
- 이 조사는 "찾을 수 있었던 공개 자료"의 스냅샷(2026-08-15)이며, 시간이 지나면 새로운
  블로그/저장소가 나타나 §1의 공백이 메워질 수 있다.
