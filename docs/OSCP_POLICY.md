# OSCP+ Exam Policy Boundary

Last verified: 2026-07-28

Authoritative references:

- [OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)
- [OSCP+ Exam FAQ](https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ)
- [AI Usage Policy in OffSec Exams](https://help.offsec.com/hc/en-us/articles/35549468971156-AI-Usage-Policy-in-OffSec-Exams)

The current guide prohibits spoofing, commercial tools or services, automatic
exploitation, mass vulnerability scanners, AI chatbots/LLMs, and features in
other tools that perform the same restricted actions. It expressly allows
Nmap/NSE, Nikto, Burp Free, and similar tools when restricted functions are not
used. The candidate remains responsible for every selected feature and tool.

OSCP Workspace therefore:

- contains no AI or LLM runtime, API integration, analysis, or generated advice;
- never determines vulnerabilities, risk, attack paths, exploit choices, or
  whether an attack succeeded;
- requires the user to select and confirm scans, commands, PTY sessions, HTTP
  requests, tunnels, evidence, and report content that the Workspace starts;
- may passively record a local command the user already chose to run, but never
  alters, selects, repeats, or extends that command;
- does not provide spoofing, automatic exploitation, automatic shells,
  automatic privilege escalation, attack chains, or mass vulnerability scans;
- treats parsed output as factual observations and preserves original data;
- keeps findings, impact, reproduction steps, and conclusions user-authored.

Do not use Codex, ChatGPT, Copilot, KAI, or another chatbot/LLM during the active
exam or reporting period. This repository can be prepared before the exam, but
the assistant used to develop it must not remain available as an exam aid.
Re-check the official guide immediately before every attempt because OffSec may
change its rules.
