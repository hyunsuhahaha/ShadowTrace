# OSCP protocol authentication audit inventory

Research date: 2026-07-30  
Local reference: Nmap 7.99, `/usr/share/nmap/scripts` and
`/usr/share/nmap/nselib`  
Application inventory: `backend/templates/services.yaml`

## Purpose and boundary

This note maps every current service group to authentication-related
enumeration that Nmap NSE can support. It distinguishes:

- **low-risk exposure checks**: anonymous, NULL, empty-password, or
  authentication-capability discovery;
- **bounded credential audits**: intrusive scripts for which the application
  can enforce a small candidate set and, where supported, per-account,
  concurrency, delay, and first-success limits;
- **context-required checks**: scripts that cannot be correct from host and
  port alone;
- **not applicable**: the protocol does not have a relevant password/community
  audit in the installed NSE set.

“Supported by NSE” does not mean “safe to run automatically.” Every brute
script cited below is categorized as `intrusive` and/or `brute`, and account
lockout remains possible. A bounded audit should therefore stay explicitly
user-selected and require scope and lockout acknowledgement.

## Exact common limits

Scripts built on Nmap's `brute` library accept:

```text
userdb=<file>
passdb=<file>
unpwdb.userlimit=<count>
unpwdb.passlimit=<count>
unpwdb.timelimit=<timespec>
brute.threads=<maximum workers>
brute.start=<initial workers>
brute.delay=<seconds between guesses>
brute.guesses=<maximum guesses per account>
brute.firstonly=true
brute.retries=<recoverable-failure retries>
brute.mode=user|pass|creds
brute.credfile=<username/password pair file>
brute.useraspass=true|false
brute.emptypass=true|false
brute.passonly=true|false
brute.unique=true|false
```

The authoritative defaults are `brute.start=5`, `brute.threads=20`,
`brute.delay=0`, `brute.guesses=0` (unlimited), `brute.firstonly=false`, and
`brute.retries=2`. `unpwdb.userlimit` and `unpwdb.passlimit` are unlimited by
default. `unpwdb.timelimit` accepts `ms`, `s`, `m`, and `h`; its default varies
with Nmap's timing template. See Nmap's official
[`brute` library documentation](https://nmap.org/nsedoc/lib/brute.html) and
[`unpwdb` library documentation](https://nmap.org/nsedoc/lib/unpwdb.html).

For a deliberately small audit, use all of the following rather than only list
limits:

```text
brute.start=2,brute.threads=2,brute.delay=2,brute.guesses=3,
brute.firstonly=true,unpwdb.userlimit=8,unpwdb.passlimit=4,
unpwdb.timelimit=2m
```

`brute.threads` is the maximum and `brute.start` is the initial worker count.
Setting both avoids relying on the engine's defaults. Script-specific timeouts
limit socket waits, not the number of authentication attempts.

Do **not** assume these common `brute.*` controls work for `snmp-brute`,
`smb-brute`, `ms-sql-brute`, `ldap-brute`, or `pgsql-brute`: their installed
implementations use custom loops rather than `brute.Engine`.

## Current service-group mapping

| YAML group | Low-risk anonymous/null/capability check | Credential/community audit | Extra context or caveat | Classification |
|---|---|---|---|---|
| `ftp` | `ftp-anon`; `ftp-anon.maxlist=0` checks login without listing directory contents | `ftp-brute` with common limits; optional `ftp-brute.timeout=<timespec>` | Anonymous access and password auditing should remain separate actions | Low-risk check + bounded brute |
| `ssh` | `ssh-auth-methods` reports methods for a supplied `ssh.user` (default `root`); it does not log in | `ssh-brute` with common limits; optional `ssh-brute.timeout=<timespec>` | Username choice affects auth-method output | Context check + bounded brute |
| `telnet` | Banner/encryption/NTLM discovery only; no generic anonymous login semantic | `telnet-brute` with common limits; `telnet-brute.timeout=<timespec>`, `telnet-brute.autosize=true|false` | Prompts vary significantly; validate product behavior | Bounded brute |
| `smtp` | `smtp-commands` discovers whether `AUTH` and mechanisms are advertised | `smtp-brute` with common limits | Optional/required selection: `smtp-brute.auth=LOGIN|PLAIN|CRAM-MD5|DIGEST-MD5|NTLM`; `smtp.domain=<domain>` may be needed. Open-relay testing is a separate behavior, not anonymous authentication. | Capability check + context-required bounded brute |
| `dns` | Existing `dns-nsid,dns-recursion` are exposure checks, not authentication | None. `dns-brute` enumerates names and is not a credential audit. | DNS update/transfer authorization is not a generic password login | Not applicable |
| `http` | `http-auth` identifies HTTP authentication at a known path; `http-auth.path=<path>` | `http-brute` supports common limits for supported HTTP auth | Must know `http-brute.path`, optionally `http-brute.hostname` for a vhost and `http-brute.method`. Forms require `http-form-brute` plus path, field names, and reliable success/failure pattern. A host/port-only template is not sufficient. | Context-required |
| `smb` | `smb-enum-shares` attempts anonymous connections and reports access possible as the NULL user | `smb-brute` exists but is bespoke | No common delay/thread/first-success controls. It tries blank and generated special passwords, can enumerate users, and has `canaries` (default 3), `brutelimit` (default 5000), and dangerous `smblockout`. List limits alone do not create the same strict attempt bound as `brute.guesses`. Do not set `smblockout`. | Low-risk NULL check; brute requires separate design |
| `nfs` | `showmount -e` / NFS export enumeration checks network authorization exposure | None | NFS commonly uses host/export and UID/GID authorization rather than a password login; mounting changes client state and should not be treated as a credential check | Low-risk exposure check; brute not applicable |
| `ldap` | Existing `ldap-rootdse` tests anonymous RootDSE metadata access | `ldap-brute` exists and honors `userdb`, `passdb`, and `unpwdb` list/time limits | It explicitly does not prevent lockout and lacks common delay/per-account/first-success controls. AD often needs `ldap.base=<DN>` or `ldap.upnsuffix=<suffix>`; do not combine them. Kerberos on port 88 is a distinct protocol and needs realm/domain context; user enumeration is not password auditing. | Low-risk anonymous check; brute not safely templateable |
| `database` | Product-specific: `mysql-empty-password` and `ms-sql-empty-password`; `redis-info` demonstrates unauthenticated INFO access when it succeeds | Product-specific scripts exist: `mysql-brute`, `ms-sql-brute`, `pgsql-brute`, `redis-brute` | This YAML group must branch on detected service. MySQL and Redis use common brute limits (`mysql-brute.timeout` also exists; Redis forces first-success). PostgreSQL uses a custom sequential loop with only `unpwdb` limits. MSSQL is bespoke, adds username-as-password attempts, observes lockout unless `ms-sql-brute.ignore-lockout` is set, and may need instance/domain context. Never expose `ignore-lockout` by default. | Product-specific; cannot use one database template |
| `rdp` | Existing `rdp-enum-encryption,rdp-ntlm-info` expose security and NTLM metadata without credential guessing | No installed `rdp-brute` or WinRM-specific brute NSE script | WinRM is HTTP(S), but `/wsman`, vhost/TLS, domain, and supported auth mechanism are required; generic HTTP Basic/Digest auditing is not a safe substitute for NTLM/Kerberos WinRM. | Discovery only / credential audit not applicable |
| `snmp` | Existing `snmp-info` normally needs a valid/default community; it is not an anonymous login check | `snmp-brute` audits community strings | Custom engine. Exact controls are `snmp-brute.communitiesdb=<file>`, `unpwdb.passlimit=<count>`, `unpwdb.timelimit=<timespec>`, plus transport controls `snmp.retries`, `snmp.timeout`, `snmp.version`. It has no documented delay, thread, per-account, or first-success control. | Bounded list/time community audit, but not low-rate common brute |
| `unknown` | Version detection only | None until protocol is identified | Authentication behavior cannot be selected safely from a port alone | Not applicable pending identification |

## Primary script references

- FTP: [`ftp-anon`](https://nmap.org/nsedoc/scripts/ftp-anon.html),
  [`ftp-brute`](https://nmap.org/nsedoc/scripts/ftp-brute.html)
- SSH: [`ssh-auth-methods`](https://nmap.org/nsedoc/scripts/ssh-auth-methods.html),
  [`ssh-brute`](https://nmap.org/nsedoc/scripts/ssh-brute.html)
- Telnet: [`telnet-brute`](https://nmap.org/nsedoc/scripts/telnet-brute.html)
- SMTP: [`smtp-commands`](https://nmap.org/nsedoc/scripts/smtp-commands.html),
  [`smtp-brute`](https://nmap.org/nsedoc/scripts/smtp-brute.html)
- HTTP: [`http-auth`](https://nmap.org/nsedoc/scripts/http-auth.html),
  [`http-brute`](https://nmap.org/nsedoc/scripts/http-brute.html),
  [`http-form-brute`](https://nmap.org/nsedoc/scripts/http-form-brute.html)
- SMB: [`smb-enum-shares`](https://nmap.org/nsedoc/scripts/smb-enum-shares.html),
  [`smb-brute`](https://nmap.org/nsedoc/scripts/smb-brute.html)
- LDAP: [`ldap-rootdse`](https://nmap.org/nsedoc/scripts/ldap-rootdse.html),
  [`ldap-brute`](https://nmap.org/nsedoc/scripts/ldap-brute.html)
- Databases:
  [`mysql-empty-password`](https://nmap.org/nsedoc/scripts/mysql-empty-password.html),
  [`mysql-brute`](https://nmap.org/nsedoc/scripts/mysql-brute.html),
  [`ms-sql-empty-password`](https://nmap.org/nsedoc/scripts/ms-sql-empty-password.html),
  [`ms-sql-brute`](https://nmap.org/nsedoc/scripts/ms-sql-brute.html),
  [`pgsql-brute`](https://nmap.org/nsedoc/scripts/pgsql-brute.html),
  [`redis-info`](https://nmap.org/nsedoc/scripts/redis-info.html),
  [`redis-brute`](https://nmap.org/nsedoc/scripts/redis-brute.html)
- RDP: [`rdp-enum-encryption`](https://nmap.org/nsedoc/scripts/rdp-enum-encryption.html),
  [`rdp-ntlm-info`](https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html)
- SNMP: [`snmp-brute`](https://nmap.org/nsedoc/scripts/snmp-brute.html)
- Complete official inventory:
  [Nmap `brute` category](https://nmap.org/nsedoc/categories/brute.html)

## Recommended implementation order

1. Add low-risk, deterministic checks: `ssh-auth-methods`, `http-auth`,
   SMB NULL-share access, database empty/unauthenticated checks.
2. Add common-engine bounded audits for SMTP and the detected MySQL/Redis
   services, preserving explicit scope and lockout acknowledgements.
3. Add HTTP only as a parameterized workflow after path/vhost/auth type (or
   form fields and failure signal) are captured.
4. Treat SNMP as a distinct community-audit workflow with count and total-time
   limits; do not claim connection or delay limits it does not implement.
5. Keep SMB, LDAP, PostgreSQL, and MSSQL custom brute scripts out of the generic
   bounded-audit template until their different lockout and attempt semantics
   are represented explicitly.
6. Expand the service catalog before adding additional installed NSE protocols
   such as IMAP, POP3, VNC, rsync, Oracle, MongoDB, SIP, SOCKS, or IPMI. The
   official brute-category index is the discovery source, but each protocol
   needs its own low-risk check, context fields, and lockout review.

## Implemented coverage

The workspace now exposes explicitly reviewed authentication checks for:

- FTP anonymous access and bounded FTP credentials;
- SSH authentication methods and bounded SSH credentials;
- Telnet banner/version investigation, manual login, and bounded credentials;
- SMTP advertised commands and bounded SMTP credentials;
- HTTP authentication discovery and bounded root-path Basic/Digest/NTLM
  credentials (HTML form login remains context-required);
- SMB NULL/Guest access and an SMB-specific limited audit with lockout
  canaries;
- anonymous LDAP RootDSE and an LDAP-specific list/time-limited audit;
- MySQL and MSSQL empty-password checks, Redis unauthenticated information,
  and product-specific MySQL, PostgreSQL, MSSQL, and Redis audits;
- bounded SNMP community strings using SNMP-specific limits;
- RDP discovery plus a Hydra audit limited to Nmap's ten built-in usernames
  and the null/same/reversed-password modes;
- bounded IMAP, POP3, VNC, MongoDB, and Rsync checks.

Every intrusive check requires both scope confirmation and a separate account
lockout acknowledgement. DNS and NFS remain discovery-only because they do not
provide a generic username/password authentication workflow. Kerberos and
WinRM remain context-required because a correct audit needs realm/domain and
authentication-method information. HTTP form login likewise requires a path,
field mapping, and a reliable failure signal.

## Local source verification

The claims above were cross-checked against the locally installed source:

- `/usr/share/nmap/nselib/brute.lua`
- `/usr/share/nmap/nselib/unpwdb.lua`
- `/usr/share/nmap/scripts/ftp-anon.nse`
- `/usr/share/nmap/scripts/{ftp,ssh,telnet,smtp,http,mysql,redis}-brute.nse`
- `/usr/share/nmap/scripts/http-form-brute.nse`
- `/usr/share/nmap/scripts/{smb,ldap,pgsql,ms-sql,snmp}-brute.nse`
- `/usr/share/nmap/scripts/{mysql,ms-sql}-empty-password.nse`

This matters because script argument support is defined by the script/library
implementation, not merely by a similarly named option in another NSE script.
