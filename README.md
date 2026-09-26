# ShadowTrace

![ShadowTrace Progress Graph](docs/assets/progress-graph.png)

Kali 터미널 활동을 기록하고 조사 과정과 증거를 연결하는 로컬 패시브 트래킹 앱.

## 주요 기능

- eBPF로 프로세스, 터미널 I/O, 소켓, 파일 변경 이벤트 수집
- 프로세스·터미널 세션·명령 활동을 시간순으로 재구성
- 프로젝트, 대상, 서비스, 자격증명, 실행 기록과 증거를 그래프로 탐색
- Nmap 결과 가져오기 및 스캔, 서비스 열거, 웹 요청 기록
- Runbook, Finding, 보고서와 증거 내보내기

## 시작하기

Kali Linux에서 Python 3.11+, Node.js, npm이 필요합니다.

```bash
./scripts/install.sh
./scripts/passive-preflight.sh
./scripts/build.sh
./scripts/start.sh
```

브라우저에서 `http://127.0.0.1:8000`을 엽니다. 개발 모드는 `./scripts/dev.sh`로 시작합니다.

## 개발

```bash
./scripts/test.sh
```

프런트엔드는 React, 백엔드는 FastAPI, 저장소는 SQLite입니다. 구현 구조는 [아키텍처](docs/ARCHITECTURE.md), 파일별 안내는 [개발 가이드](docs/ENGINEERING_ONBOARDING.md)에 정리되어 있습니다.
