# Research: Is DotDotPwn allowed on the OSCP/OSCP+ exam?

**Bottom line (read this first):** The two live, primary OffSec help-center pages checked
below **do not mention "DotDotPwn" anywhere, in any form.** This is a **silence, not
permission** situation — the sources are silent on this specific tool, and silence does not
constitute an official ruling either way. Do not treat this note as clearance to use
DotDotPwn on a real exam. Apply the general restricted-tool categories yourself (see §3,
"my assessment," clearly labeled as inference, not fact) and/or **contact OffSec support
directly for a binding answer** before relying on it in a real exam attempt.

**Scope of sources:** PRIMARY (first-party) only, fetched live via browser on the retrieval
date below (WebFetch returned HTTP 403 on both URLs — Cloudflare/bot-blocked — so pages were
loaded and text-extracted through an interactive browser tab instead; the extracted text is
the full rendered `<article>` content of each page, not a summary).

- OSCP+ Exam Guide — `https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide`
  (retrieved 2026-08-13; page footer shows "3 months ago Updated")
- OSCP+ Exam FAQ — `https://help.offsec.com/hc/en-us/articles/4412170923924-OSCP-Exam-FAQ`
  (retrieved 2026-08-13; page footer shows "13 days ago Updated")

Neither page links to any *other* help.offsec.com article that itself enumerates a
banned/restricted-tools list. The FAQ links out to "AI Usage Policy in OffSec Exams" and
"OffSec KAI FAQ", but both are scoped specifically to AI chatbots/LLMs, not to a general
tool list — the only place a general banned/restricted-tools list actually lives is the
Exam Guide's "Exam Restrictions" section, quoted in full below. The FAQ itself repeatedly
directs the reader back to that same Exam Guide section rather than duplicating an
independent list.

**Verification legend:** [V] = verbatim quote from the fetched primary-source text
(verified fact); [I] = inference/analysis drawn by the author of this note, not sourced;
[D] = discrepancy noted against the 2026-08-07 snapshot referenced in the task.

---

## 1. Does "DotDotPwn" appear in either page?

**No.** A search of the full extracted text of both pages (Exam Guide and FAQ) for the
literal string "DotDotPwn" (case-insensitive) returns **zero matches** in either document.
[V] The tool is not named, discussed, allowed, or banned anywhere in either primary source.

## 2. Verbatim banned/restricted-tools sections (current live text)

### 2.1 OSCP+ Exam Guide → "Exam Restrictions" (verbatim)

> **Exam Restrictions**
>
> You cannot use any of the following on the exam:
>
> - Spoofing (IP, ARP, DNS, NBNS, etc)
> - Commercial tools or services (Metasploit Pro, Burp Pro, etc.)
> - Automatic exploitation tools (e.g. db_autopwn, browser_autopwn, SQLmap, SQLninja etc.)
> - Mass vulnerability scanners (e.g. Nessus, NeXpose, OpenVAS, Canvas, Core Impact, SAINT, etc.)
> - AI Chatbots (OffSec KAI, ChatGPT, YouChat, etc.)
> - Features in other tools that utilize either forbidden or restricted exam limitations
>
> You are not required to disable tools with built-in AI features like Notion or Google AI
> Overview.
> However, using LLMs and AI chatbots (OffSec KAI, ChatGPT, Deepseek, Gemini, etc.) is
> strictly prohibited. This is considered receiving third-party help and sharing exam
> information, both of which violate our Academic Policy. For more information, please
> refer to AI Usage Policy in OffSec Exams.
>
> Any tools that perform similar functions as those above are also prohibited. You are
> ultimately responsible for knowing what features or external utilities any chosen tool is
> using. The primary objective of the OSCP+ exam is to evaluate your skills in identifying
> and exploiting vulnerabilities, not in automating the process.
>
> You may however, use tools such as Nmap (and its scripting engine), Nikto, Burp Free,
> DirBuster etc. against any of your target systems.
>
> NOTE: While you may use Discord as a resource for searching for information during the
> exam, under no circumstances are you permitted to seek or receive assistance from others
> on the platform.
>
> For more information regarding the allowed tools, please visit our OSCP+ Exam FAQ article.
>
> Please note that we will not comment on allowed or restricted tools, other than what is
> included inside this exam guide.

[V] Source: OSCP+ Exam Guide, "Exam Restrictions" section, retrieved 2026-08-13.

### 2.2 OSCP+ Exam Guide → "Metasploit Restrictions" (verbatim)

> **Metasploit Restrictions**
>
> The usage of Metasploit and the Meterpreter payload are restricted during the exam. You
> may only use Metasploit modules (Auxiliary, Exploit, and Post) or the Meterpreter payload
> against one single target machine of your choice. Once you have selected your one target
> machine, you cannot use Metasploit modules ( Auxiliary, Exploit, or Post ) or the
> Meterpreter payload against any other machines.
>
> Metasploit/Meterpreter should not be used to test vulnerabilities on multiple machines
> before selecting your one target machine ( this includes the use of check ) . You may use
> Metasploit/Meterpreter as many times as you would like against your one target machine.
>
> If you decide to use Metasploit or Meterpreter on a specific target and the attack fails,
> then you may not attempt to use it on a second target. In other words, the use of
> Metasploit and Meterpreter becomes locked in as soon as you decide to use either one of
> them.
>
> Metasploit cannot be used for pivoting, because it would thereby be used on more than one
> target.
>
> You may use the following against all of the target machines with the exception that
> meterpreter payload could be used only against one target machine:
>
> - multi handler (aka exploit/multi/handler)
> - msfvenom
>
> All the above limitations also apply to different interfaces that make use of Metasploit
> (such as Armitage, Cobalt Strike, Metasploit Community Edition, etc).

[V] Source: OSCP+ Exam Guide, "Metasploit Restrictions" section, retrieved 2026-08-13.

### 2.3 OSCP+ Exam Guide → "Point Disqualification" (verbatim, relevant excerpt)

> You will receive no points for a specific target for the following:
>
> - Using a restricted tool
> - Using Metasploit Auxiliary, Exploit, or Post modules on multiple machines
> - Using the Meterpreter payload on multiple machines
> - Failure to provide the local.txt and proof.txt file contents in both the control panel
>   and in an interactive shell screenshot
> - Lack of documentation

[V] Source: OSCP+ Exam Guide, "Point Disqualification" section, retrieved 2026-08-13.
Included because it establishes the *consequence* of the restrictions above (zero points
for that target, not automatic exam failure) — relevant context for risk assessment, not a
separate tool list.

### 2.4 OSCP+ Exam FAQ → "What are the exam restrictions?" (verbatim, in full)

> More information can be found in the OSCP+ Exam Guide and the exam restrictions video
> below.

[V] Source: OSCP+ Exam FAQ, retrieved 2026-08-13. The FAQ does **not** restate or add to the
restricted-tool list itself — it defers entirely to the Exam Guide section quoted in §2.1.

### 2.5 OSCP+ Exam FAQ → "Which tools are allowed for the OSCP+ exam?" (verbatim)

> All tools that do not perform any restricted actions are allowed during the exam. The
> following tools are allowed, but the list is not limited to these:
>
> - BloodHound (Legacy and Community Edition only)
> - SharpHound
> - PowerShell Empire
> - Covenant
> - Powerview
> - Rubeus
> - evil-winrm
> - Responder (Poisoning and Spoofing is not allowed in the challenges or on the exam)
> - Crackmapexec
> - Mimikatz
> - Impacket
> - PrintSpoofer
>
> More information regarding the allowed and restricted tools for the OSCP+ exam can be
> found in the Exam Restrictions section in the OSCP+ Exam Guide

[V] Source: OSCP+ Exam FAQ, "Which tools are allowed for the OSCP+ exam?" section, retrieved
2026-08-13. This is a non-exhaustive **allow-list** of named tools (mostly AD-focused) — it
does not mention DotDotPwn, ffuf, wfuzz, gobuster, or any LFI/traversal fuzzer, allowed or
banned.

### 2.6 OSCP+ Exam FAQ → "Can I use KAI or any other chatbots during the OSCP+ exam?" (verbatim)

> Use of KAI or any other chatbots is not allowed during the exam and the exam reporting
> phase.
>
> For more information about KAI, please visit the following URL: OffSec KAI FAQ

[V] Source: OSCP+ Exam FAQ, retrieved 2026-08-13. Included for completeness; not relevant to
DotDotPwn (it is not a chatbot/LLM).

---

## 3. My assessment — how would a tool like DotDotPwn plausibly be classified?

**This entire section is inference and analysis by the author of this note. It is NOT an
official OffSec ruling, is NOT sourced to any primary-source text (because that text never
names the tool), and should not be treated as authoritative.** [I]

DotDotPwn is a Perl-based fuzzer that automates probing for and can help confirm directory
traversal / LFI vulnerabilities across a target list of payload permutations, protocols
(HTTP, FTP, TFTP, payload-stdout), and traversal depths. It does not itself grant shells or
chain post-exploitation — it identifies (and can help confirm) a specific, narrow
vulnerability class.

Weighing it against the categories actually named in the Exam Guide (§2.1):

- **"Mass vulnerability scanners" (Nessus, NeXpose, OpenVAS, Canvas, Core Impact, SAINT)**
  — [I] this looks like the weakest fit. Those named tools scan broadly across many CVEs
  and vulnerability classes simultaneously, typically producing a scored/prioritized
  findings report. DotDotPwn targets one specific vulnerability class (path traversal / LFI)
  against a single target. It is closer in spirit to a specialized fuzzer than to a
  general-purpose CVE scanner.
- **"Automatic exploitation tools" (db_autopwn, browser_autopwn, SQLmap, SQLninja, "similar
  functions")** — [I] this is the more arguable classification. SQLmap is explicitly named
  and is, like DotDotPwn, a single-vulnerability-class automation tool (SQL injection
  detection *and* exploitation/data extraction) rather than a broad multi-CVE scanner.
  DotDotPwn's core function (automated, permutation-based probing to detect/confirm a
  vulnerability class) is functionally analogous to what SQLmap does for SQLi — which is
  precisely the kind of "similar function" the Guide's catch-all sentence ("Any tools that
  perform similar functions as those above are also prohibited") seems aimed at. However,
  DotDotPwn's traversal-detection function stops short of SQLmap's automated
  exploitation/extraction/shell capabilities in many of its default modes, so the analogy is
  not exact — it's a plausible but not certain fit.
- **General fuzzing/enumeration tools (ffuf, wfuzz, gobuster, DirBuster)** — [I] the Exam
  Guide explicitly names DirBuster as an allowed tool ("You may however, use tools such as
  Nmap ... Nikto, Burp Free, DirBuster etc."), and content/directory fuzzers of this kind are
  standard, uncontested OSCP recon tooling. DotDotPwn differs from these in that it is
  purpose-built to detect *and can attempt to exploit* one specific vulnerability class
  (traversal/LFI) rather than doing generic content discovery — so a direct equivalence to
  DirBuster/ffuf is not obviously correct either.

**Net assessment (inference only):** DotDotPwn sits in ambiguous territory between "allowed
general fuzzer" (DirBuster-like) and "prohibited automatic exploitation tool" (SQLmap-like),
leaning arguably closer to the SQLmap analogy given both are narrow, single-vulnerability-
class automation tools explicitly built to detect and, depending on mode, confirm/exploit
that class — but this is a *reasoned guess*, not a documented answer, and the primary
sources give no basis to resolve it definitively either way.

## 4. Recommendation

The primary sources are silent on DotDotPwn specifically. Per the Exam Guide itself: **"Please
note that we will not comment on allowed or restricted tools, other than what is included
inside this exam guide."** [V] This means OffSec has explicitly pre-committed to not
adjudicating tool-specific questions beyond what's already written — so even a direct support
inquiry may only get a category-level answer rather than a DotDotPwn-specific yes/no.
Nonetheless, before relying on this tool in a real exam attempt:

1. Apply the category tests in §3 yourself, using your own judgment about how you intend to
   use the tool (pure detection vs. automated exploitation/extraction), and
2. If in doubt, contact OffSec support directly (`help AT offsec DOT com` or
   `https://chat.offsec.com/`) for the most current, binding guidance — understanding they
   may decline to give a tool-specific ruling per the quoted policy above.

Silence in the primary sources is not permission. Do not assume DotDotPwn is allowed merely
because it isn't named in the banned-tools list.

## 5. Differences vs. the 2026-08-07 snapshot referenced in the task

The task described a possibly-stale snapshot (matching the categories already captured in
this repo's `docs/OSCP_POLICY.md` and `CLAUDE.md`, last verified 2026-07-28 per
`OSCP_POLICY.md`). Comparing that snapshot's five categories against the current live text:

- **Spoofing/poisoning (IP/ARP/DNS/NBNS)** — [D] confirmed unchanged, matches verbatim:
  "Spoofing (IP, ARP, DNS, NBNS, etc)".
- **Commercial tools (Metasploit Pro, Burp Suite Pro)** — [D] confirmed unchanged, matches
  verbatim (Guide says "Burp Pro" not "Burp Suite Pro" — trivial naming difference only).
- **Automated exploitation tools (db_autopwn, browser_autopwn, SQLmap, SQLninja, "and
  functional equivalents")** — [D] the named examples are unchanged, but the phrase
  "functional equivalents" is not how the current page phrases the catch-all — the live text
  uses one blanket sentence *after the entire bulleted list* ("Any tools that perform similar
  functions as those above are also prohibited"), applying to **all** categories at once,
  not a per-category "functional equivalents" clause as the snapshot's paraphrase implies.
  Substance is the same; structure/wording differs slightly.
- **Mass/large-scale vulnerability scanners (Nessus, NeXpose, OpenVAS, Canvas, Core Impact,
  SAINT)** — [D] confirmed unchanged in substance; the Guide's own label is "Mass
  vulnerability scanners," not "large-scale vulnerability scanners" (paraphrase only, not a
  material difference).
- **Metasploit-specific restriction (one target only, no pivoting)** — [D] confirmed
  unchanged and, if anything, more detailed than a short summary would suggest — the current
  Guide adds explicit detail not always captured in short summaries: the restriction locks in
  as soon as Metasploit/Meterpreter is used even once (including a failed attempt), the
  `check` command itself counts as "testing" and is barred pre-selection, and the restriction
  explicitly extends to interface wrappers (Armitage, Cobalt Strike, Metasploit Community
  Edition).

**New items not in the five-category snapshot:**

- **AI Chatbots** is now its own explicit bullet in the Exam Restrictions list ("AI Chatbots
  (OffSec KAI, ChatGPT, YouChat, etc.)"), plus a full following paragraph on LLM/chatbot
  prohibition and a link to a dedicated "AI Usage Policy in OffSec Exams" article. This repo's
  `docs/OSCP_POLICY.md` already accounts for this separately, but it's worth noting the
  five-category snapshot in the task prompt omitted it.
- A sixth bullet, **"Features in other tools that utilize either forbidden or restricted exam
  limitations,"** appears directly in the bulleted list itself (distinct from, and in addition
  to, the later blanket "similar functions" sentence) — i.e., the catch-all is stated twice,
  once inside the list and once after it.
- The **allowed-tools list** in the FAQ (§2.5 above: BloodHound, SharpHound, PowerShell
  Empire, Covenant, Powerview, Rubeus, evil-winrm, Responder, Crackmapexec, Mimikatz,
  Impacket, PrintSpoofer) is FAQ content not mentioned in the task's snapshot description at
  all — worth having on record since it's the closest thing to an official allow-list, and it
  does not include DotDotPwn or any LFI/traversal fuzzer, named either way.

No categories were removed relative to the snapshot; the changes found are additions
(AI chatbots, the second catch-all bullet, the named allow-list) and minor wording/paraphrase
differences, not substantive removals or loosenings.
