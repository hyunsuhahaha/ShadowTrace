# Research: Auditing this app's tool catalog against the OSCP+ Exam Guide's 5 restricted-action categories

**Bottom line (read this first):** The OSCP+ FAQ's named allow-list ("BloodHound, SharpHound,
PowerShell Empire, Covenant, Powerview, Rubeus, evil-winrm, Responder, Crackmapexec, Mimikatz,
Impacket, PrintSpoofer") is explicitly **non-exhaustive** — the real test is whether a tool
performs one of five restricted actions named in the Exam Guide, not whether its name appears
on that list. Applying that test to every external tool this app's catalogs
(`backend/templates/services.yaml`, `backend/templates/credential_hunt.yaml`) can invoke, only
two items show a plausible connection to a restricted category, and one of those two turned out
to be a misreading on first pass, corrected below. Everything else in the catalog is clear.

**Scope of sources:** Same primary sources as
[`RESEARCH_DOTDOTPWN_EXAM_COMPLIANCE.md`](RESEARCH_DOTDOTPWN_EXAM_COMPLIANCE.md) — the OSCP+
Exam Guide and Exam FAQ, retrieved 2026-08-13. See that file for the full verbatim quotes of the
"Exam Restrictions," "Metasploit Restrictions," and FAQ allow-list sections; they are not
re-quoted line-for-line here except where directly relevant. This note also checked a
third-party community list (`github.com/RajChowdhury240/OSCP-CheatSheet/blob/main/Tools.md`,
213 GitHub stars) proposed as a reference during this audit — see §4, it was rejected as a
source.

**Verification legend (same as the DotDotPwn note):** [V] = verbatim/directly-sourced fact;
[I] = inference/analysis, not sourced to primary text; [D] = a point that was corrected during
this same investigation (shown so the reasoning trail stays honest, not just the conclusion).

---

## 1. The five restricted-action categories (from the Exam Guide's "Exam Restrictions")

1. Spoofing (IP, ARP, DNS, NBNS, etc.)
2. Commercial tools or services (Metasploit Pro, Burp Pro, etc.)
3. Automatic exploitation tools (e.g. db_autopwn, browser_autopwn, SQLmap, SQLninja, etc.)
4. Mass vulnerability scanners (e.g. Nessus, NeXpose, OpenVAS, Canvas, Core Impact, SAINT, etc.)
5. AI Chatbots (OffSec KAI, ChatGPT, YouChat, etc.)

Plus two catch-all clauses: "Features in other tools that utilize either forbidden or
restricted exam limitations" (inside the bulleted list) and "Any tools that perform similar
functions as those above are also prohibited" (after it). [V]

The FAQ's named allow-list is explicitly a floor, not a ceiling: "All tools that do not perform
any restricted actions are allowed during the exam. The following tools are allowed, **but the
list is not limited to these**." [V]

## 2. Full tool inventory of this app's catalogs

Compiled by grepping every `tool:` field in `backend/templates/services.yaml` (the
"protocol toolbox" catalog) plus every `command:` in `backend/templates/credential_hunt.yaml`
(the post-exploitation catalog, which uses only OS-native commands — `grep`, `find`,
`powershell`/`reg`/`cmdkey` — not external binaries) as of 2026-08-13. `services.yaml` names 41
distinct external tools.

### 2.1 Directly covered by the FAQ's named allow-list

- `impacket-GetNPUsers`, `impacket-getST`, `impacket-lookupsid`, `impacket-mssqlclient`,
  `impacket-secretsdump`, `impacket-smbserver`, `impacket-ticketer` — all part of the
  "Impacket" suite, named explicitly. [V]
- `responder` — named explicitly, with a caveat; see §3.
- `netexec` — the FAQ names "Crackmapexec." NetExec is the same upstream project under its
  post-2023 name (the old `crackmapexec` PyPI package now points to NetExec; this box has only
  `netexec` installed, no `crackmapexec` binary at all). [I] Functionally identical, but the
  FAQ text has not been updated to the new name — a naming gap, not a functional one. None of
  the netexec commands actually wired into this catalog are automated vulnerability-check
  modules (no ZeroLogon/MS17-010/PrintNightmare checks are used here) — confirmed by grep
  against `services.yaml`.

### 2.2 Same category as an Exam-Guide-named example ("Nmap ... Nikto, Burp Free, DirBuster etc.")

- `nmap` — named explicitly. [V]
- `gobuster`, `feroxbuster`, `ffuf` — same functional class as the explicitly-named DirBuster
  (directory/content fuzzers). [I]

### 2.3 Standard OS/protocol clients — not "tools" in the sense the restrictions discuss

`curl`, `ssh`, `ftp`, `telnet`, `smbclient`, `smbget`, `rpcclient`, `showmount`, `mount.nfs`,
`mycli`, `mysql-client`, `postgresql-client`, `redis-cli`, `python3`, `snmp`, `whatweb`, `find`,
`rsync`, `ike-scan`, plus `credential_hunt.yaml`'s OS-native commands (`grep`, `find`,
`powershell`, `reg`, `cmdkey`). None scan for vulnerabilities, exploit automatically, spoof, or
are commercial. [I]

### 2.4 Not named anywhere, not obviously covered by an Exam-Guide example — audited individually

`dotdotpwn`, `hydra`, `kerbrute`, `bloodhound-python`, `git-dumper`, `cloud_enum`, `aws`
(awscli). Full five-category test for each is in §3.

## 3. Five-category test, applied item by item

| Tool | Spoofing/poisoning | Commercial | Automatic exploitation | Mass vuln scanner | AI chatbot | Net |
|---|---|---|---|---|---|---|
| `dotdotpwn` | No | No | **Plausible fit** — see below | No (single vuln class, single target) | No | Leans toward category 3 by analogy, not certain |
| `hydra` | No | No | No — tests candidate credentials, doesn't chain into automated exploitation; the operator still uses the result manually | No | No | Clear |
| `kerbrute` | No | No | No — Kerberos pre-auth username/password enumeration, not exploitation | No | No | Clear |
| `bloodhound-python` | No | No | No — pure LDAP/SMB/WinRM data collection, same category as the explicitly-allowed SharpHound | No | No | Clear |
| `git-dumper` | No | No | No — reconstructs an already-HTTP-exposed `.git` tree; automates fetching, not exploiting | No | No | Clear (mild spirit-of-the-rule tension only, see below) |
| `netexec` (as used here) | No | No | No — the modules actually wired into this app are targeted credential/attribute checks (e.g. gMSA password read), not autonomous CVE exploitation | No | No | Clear — see §2.1 for the naming-only caveat |
| `cloud_enum`, `aws` (awscli) | No | No | No — enumeration/listing only | No | No | Clear |

### 3.1 `dotdotpwn` — the one plausible hit

Automates generating traversal payloads across multiple depths/encodings, sends them against a
single URL, detects success by pattern match, and stops automatically on the first hit. [V,
from tool behavior] Structurally this is close to what SQLmap does for SQL injection
(automated payload generation → injection-point testing → automated confirmation) — the
explicitly-named example of category 3, and the catch-all clause ("similar functions... also
prohibited") appears aimed at exactly this shape of tool. [I] It is a weak fit for category 4
("mass vulnerability scanner") because it targets one vulnerability class against one target,
not many CVEs across many hosts. No fit for categories 1, 2, 5. **Net: closest functional
analogy is category 3, but this is inference — DotDotPwn is not named in either primary
source.** Full writeup: [`RESEARCH_DOTDOTPWN_EXAM_COMPLIANCE.md`](RESEARCH_DOTDOTPWN_EXAM_COMPLIANCE.md).

### 3.2 `git-dumper` — noted but not counted as a hit

No category applies directly. The one soft concern is the Exam Guide's stated purpose ("The
primary objective... is to evaluate your skills in identifying and exploiting vulnerabilities,
not in automating the process") — git-dumper automates a mechanical, already-authorized HTTP
fetch loop (nothing here is a forged response or a chained exploit), so it does not trip any of
the five named categories, but the "automating the process" framing is worth being aware of as
a spirit-level (not category-level) consideration. [I]

## 4. Rejected source: a starred GitHub "OSCP cheat sheet"

During this audit, a community repository
(`github.com/RajChowdhury240/OSCP-CheatSheet/blob/main/Tools.md`, 213 stars) was proposed as
grounds for treating everything it lists as exam-safe. Fetched and inspected directly: the file
is a single generic "Weapons" table (columns: Type, Name, Description, Popularity-as-a-GitHub-
star-badge, Language) with zero occurrences of the string "OSCP" anywhere in the file. [V] It
lists `nuclei` (a mass CVE-template scanner — squarely category 4) and OSS alternatives to
Burp Pro alongside legitimate recon tools, with no allowed/restricted distinction at all — it
is a general pentesting-tools directory that happens to live in a repo named "OSCP-CheatSheet,"
not a curated exam-compliance list. Star count reflects GitHub popularity, not any vetting
against OffSec's rules. **Rejected as a compliance source** — consistent with CLAUDE.md's
instruction to check the official Exam Guide/FAQ rather than a third party when allowance is
unclear.

## 5. Responder: the poisoning-caveat back-and-forth (documented so the trail is honest)

The FAQ names Responder as allowed with a parenthetical: "Responder (Poisoning and Spoofing is
not allowed in the challenges or on the exam)." [V] This sits next to the Exam Guide's category
1, "Spoofing (IP, ARP, DNS, **NBNS**, etc)" [V] — NBNS being literally what Responder poisons
by design.

**First-pass conclusion in this audit (later walked back):** treated this as Responder falling
squarely under category 1 because its core function is NBNS/LLMNR poisoning. [D]

**Why that was too hasty:** if Responder's baseline designed operation (answering a target's own
LLMNR/NBT-NS broadcast fallback queries to capture a hash) were actually banned, naming it as an
allowed tool would be self-contradictory — there would be no non-banned use left for the FAQ to
be permitting. This is also the exact technique used in HTB's canonical "Responder" box and in
standard OSCP Active Directory methodology, which strongly suggests it is the intended,
expected use, not a violation. [I]

**More coherent reading (community/practical interpretation, not a primary-source quote):** the
"poisoning and spoofing not allowed" caveat most plausibly targets broader, more aggressive
techniques — e.g. ARP cache poisoning that redirects an entire network segment's traffic, or
poisoning/intercepting traffic outside the tester's own assigned engagement scope — rather than
Responder's baseline function of answering broadcast queries that the tester's own target
machine sends. [I] This reading is not stated explicitly anywhere in either primary source; it
is the most coherent way to resolve an apparent internal contradiction in the FAQ text, not a
documented fact. OffSec's own policy ("we will not comment on allowed or restricted tools,
other than what is included inside this exam guide") means this specific ambiguity has no
official clarification available.

**Practical implication for this app's two SMB-hash-capture paths (`ResponderPanel` /
`SmbServerPanel` in `frontend/src/`):**

- **Responder** (`responder -I {interface} -v`) — relies on the target's own broadcast
  LLMNR/NBT-NS fallback traffic. Standard, named-allowed use per the above reading.
- **impacket-smbserver** (`impacket-smbserver share {output_dir} -smb2support`) — opens a real,
  unauthenticated SMB listener; nothing is spoofed or poisoned. A target only reaches it because
  of a *separate* forced-authentication bug (UNC-path file inclusion, PetitPotam, a malicious
  `.scf`/`.lnk`, etc.), not because any protocol response was forged. This path has **no
  overlap at all** with category 1, on top of being covered by the explicitly-named "Impacket"
  entry — the cleaner of the two when avoiding any ambiguity matters.

Neither tool needs to be avoided; they answer different questions (how the target is made to
authenticate to you), not a compliance question.

## 6. Recommendation

Only `dotdotpwn` shows a plausible (inference-only) connection to a restricted category
(automatic exploitation). Everything else audited in this app's catalog — including the items
initially flagged as "gray zone" (`hydra`, `kerbrute`, `bloodhound-python`, `git-dumper`,
`netexec`'s naming gap, and Responder's core function) — does not fit any of the five
categories under this analysis. As with the DotDotPwn note, none of this is an official OffSec
ruling; re-check the primary sources yourself before relying on any specific tool in a real
exam attempt, and contact OffSec support directly for anything load-bearing.
