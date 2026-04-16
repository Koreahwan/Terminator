# 해킹/펜테스트/오펜시브 보안 “AI 프레임워크/플랫폼” 목록 (업데이트)

> 범위: (1) 에이전트형 펜테스트 자동화, (2) 취약점 스캐닝/리포팅 자동화, (3) 보안 테스트 오케스트레이션/도구 통합, (4) 인접(코드/테스트 강화) 보안 자동화

---

## A. 오픈소스/리서치 중심 (Agentic Pentest / Red Team Automation)

- **PentAGI** — “Fully autonomous AI Agents system”으로 펜테스트 단계를 자동으로 계획·실행(도커 격리, 보안 도구 번들 등) :contentReference[oaicite:0]{index=0}  
  - Repo: https://github.com/vxcontrol/pentagi :contentReference[oaicite:1]{index=1}

- **CyberStrikeAI** — Go 기반 “AI-native security testing platform”; 100+ 보안 도구 통합, 오케스트레이션 엔진/역할 기반 테스트 등을 표방 :contentReference[oaicite:2]{index=2}  
  - Repo: https://github.com/Ed1s0nZ/CyberStrikeAI :contentReference[oaicite:3]{index=3}

- **Shannon** — 자율형 AI 펜테스팅/익스플로잇 시도까지 포함한 오픈소스 프로젝트로 알려져 있음  
  - Repo: https://github.com/KeygraphHQ/shannon :contentReference[oaicite:4]{index=4}

- **CAI (Cybersecurity AI)** — 버그바운티/공격 워크플로우에 에이전트를 붙이는 오픈소스 프레임워크  
  - Repo: https://github.com/aliasrobotics/cai :contentReference[oaicite:5]{index=5}

- **PentestGPT** — LLM 기반 펜테스트 에이전트 계열(오픈소스/논문 계열로 널리 인용됨)  
  - Repo: https://github.com/GreyDGL/PentestGPT  *(이 항목은 이전 대화에서 확인했고, 필요하면 최신 상태를 추가로 크롤링해서 보강 가능)*

- **PentestAgent** — 블랙박스 보안 테스트 자동화 지향의 AI 에이전트 프레임워크  
  - Repo: https://github.com/GH05TCREW/pentestagent  *(동일)*

- **HexStrike AI (MCP Agents)** — MCP로 다수 보안 도구를 에이전트가 호출·조합하도록 설계된 “도구 브릿지/오케스트레이터” 성격  
  - Repo: https://github.com/0x4m4/hexstrike-ai  *(동일)*

- **NeuroSploit** — LLM 연동 보안/펜테스트 프레임워크(에이전트형 구성 강조)  
  - Repo: https://github.com/CyberSecurityUP/NeuroSploit  *(동일)*

- **Nebula (berylliumsec/nebula)** — AI 모델 연동 “펜테스트 어시스턴트” 컨셉(동명 프로젝트가 많아 repo 확인 필수)  
  - Repo: https://github.com/berylliumsec/nebula  *(동일)*

---

## B. 오픈소스 “취약점 스캐너/리포팅 자동화” (Agentic이라기보다 Scanner 중심)

- **Artemis (CERT Polska)** — 모듈형 웹사이트 보안 스캐너 + “조치 가능한 리포트” 생성에 초점을 둔 오픈소스 :contentReference[oaicite:11]{index=11}  
  - Repo: https://github.com/CERT-Polska/Artemis :contentReference[oaicite:12]{index=12}

- **Artemis Modules Extra** — Artemis에 붙는 추가 모듈 모음(라이선스 등 이유로 코어에 미포함) :contentReference[oaicite:13]{index=13}  
  - Repo: https://github.com/CERT-Polska/Artemis-modules-extra :contentReference[oaicite:14]{index=14}

---

## C. 범용 “자율 에이전트 프레임워크” (보안 특화는 아니지만 펜테스트 에이전트 구현에 자주 활용)

- **AutoGPT** — 목표를 주면 하위 작업으로 쪼개 실행하는 “continuous AI agents” 플랫폼/프레임워크 :contentReference[oaicite:15]{index=15}  
  - Repo: https://github.com/Significant-Gravitas/AutoGPT :contentReference[oaicite:16]{index=16}

---

## D. 인접: 코드/테스트/보안 품질 자동화 (직접 “해킹”이라기보단 보안 테스트 강화 쪽)

- **Mutahunter** — “LLM-based mutation testing”을 표방하는 오픈소스(언어 불문 변이 테스트) :contentReference[oaicite:17]{index=17}  
  - Repo: https://github.com/codeintegrity-ai/mutahunter :contentReference[oaicite:18]{index=18}

---

## E. 상용/플랫폼형 (Autonomous / AI Pentesting Platform)

- **XBOW** — 자율 오펜시브 시큐리티/AI 펜테스팅 플랫폼(상용)  
  - Site: https://xbow.com/  *(이전 대화에서 확인한 항목; 필요 시 최신 페이지 인용 추가 가능)*

- **Xint (Theori)** — AI 기반 펜테스트/보안 점검 플랫폼(상용)  
  - Site: https://xint.io/  *(동일)*

- **Pentera** — 자동화/지속적 펜테스트(Continuous & Automated Pen Testing) 플랫폼  
  - Site: https://pentera.io/penetration-testing/  *(동일)*

- **Horizon3.ai NodeZero** — 연속 자율 펜테스트(continuous autonomous pentesting) 플랫폼  
  - Site: https://horizon3.ai/nodezero/  *(동일)*

- **PentestAI (pentest-ai.fr)** — AI penetration testing을 내세운 서비스/베타  
  - Site: https://pentest-ai.fr/  *(동일)*

---

## F. BugTrace 계열 (요청 반영)

- **BugTraceAI v2 (사이트/플랫폼)** — 에이전트 기반 보안 테스트 플랫폼으로 브랜딩되는 흐름  
  - Site: https://bugtraceai.com/  *(이전 대화에서 확인; 필요 시 최신 인용 추가 가능)*

- **BugTrace-AI (repo, archived)** — 구 버전/아카이브 처리된 repo  
  - Repo: https://github.com/yz9yt/BugTrace-AI  *(동일)*
