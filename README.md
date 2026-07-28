# OSCP Workspace

Kali Linux에서 승인된 침투테스트 대상과 수동 열거 작업을 관리하는 로컬 전용
워크스페이스입니다. FastAPI + React 구조를 유지하며 상용 도구 수준의 작업 흐름을
단계적으로 구현합니다.

## 장기 제품 범위

- 대상, 범위 및 프로젝트 관리
- Scan Center와 스캔 결과 비교
- 서비스별 수동 열거 작업
- 사용자가 직접 작성하고 반복 실행하는 HTTP 요청
- Active Directory 정보 정리
- 터널 및 대화형 세션 관리
- 증적, 스크린샷 및 보고서 관리

OSCP+ 시험 제한을 제품 경계로 적용합니다. 정보 수집, 정적 명령 템플릿, 사용자가
선택한 열거 명령, 결과 파싱·시각화는 허용합니다. 자동 취약점 판정, 자동 공격 선택이나
실행, 자동 셸 획득, 대규모 취약점 스캐닝, AI 분석 및 스푸핑은 구현하지 않습니다.

시험 직전에는 반드시 [공식 정책 경계와 확인일](docs/OSCP_POLICY.md)을 다시
검토하세요. 특히 시험 및 보고 기간에는 ChatGPT/Codex를 포함한 AI 챗봇과 LLM 사용이
금지되므로 이 개발 세션을 종료해야 합니다.

## 구현 순서

1. Scan Center
2. Service Enumeration
3. Web Testing Workspace
4. Evidence Management
5. AD Information
6. Tunnels and Sessions
7. Reporting

상세 기능 경계와 완료 조건은 [제품 로드맵](docs/ROADMAP.md), 모듈 구조는
[아키텍처 문서](docs/ARCHITECTURE.md)를 참고하세요.

현재 1–7단계의 사용 가능한 첫 버전과 전체 검색·감사·백업까지 연결되어 있습니다.
각 기능은 관찰·기록·사용자 확인 실행에 한정되며 자동 취약점 판정이나 공격 선택을
하지 않습니다. 상세 구현 및 검증 이력은 [작업 기록](docs/WORKLOG.md)에 있습니다.

## 빠른 시작

Kali, Debian 또는 Ubuntu에서 실행합니다.

```bash
./scripts/install.sh
./scripts/dev.sh
```

개발 UI는 `http://127.0.0.1:5173`, API는 `http://127.0.0.1:8000`입니다.
프로덕션 모드는 다음과 같습니다.

```bash
./scripts/build.sh
./scripts/start.sh
```

설치·개발·시작 스크립트는 Alembic 마이그레이션을 자동 적용합니다. Alembic 도입 전에
만들어진 로컬 데이터베이스는 기존 데이터를 유지한 채 현재 스키마로 채택합니다.

OS 도구가 없으면 UI에서 설치 상태, 실행 파일 경로와 추천 `apt` 명령을 확인할 수
있습니다. 설치 스크립트는 OS 패키지를 자동 설치하거나 sudo 암호를 요청하지 않습니다.
