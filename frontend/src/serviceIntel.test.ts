import { describe, expect, it } from "vitest";
import {
  isDnsLikeService,
  isHttpLikeService,
  keepSelectedService,
  missingServiceFacts,
  parseFeroxbusterResults,
  parseFfufVhostResults,
  parseGobusterDnsResults,
  parseKerbruteResults,
  parseNetexecSprayHits,
  parseSecretsdumpHashes,
  parseSmbEnumSharesAccess,
  parseSmbFiles,
  parseSmbShares,
  parseScriptObservations,
  rankInvestigationCommands,
  remainingInvestigationCommands,
  summarizeExecutionResult,
} from "./serviceIntel";

describe("isHttpLikeService", () => {
  it("trusts the plain service name for the usual http/https/ssl-http cases", () => {
    expect(isHttpLikeService("http")).toBe(true);
    expect(isHttpLikeService("HTTPS")).toBe(true);
    expect(isHttpLikeService("ssl/http")).toBe(true);
    expect(isHttpLikeService("ssh")).toBe(false);
  });

  it("falls back to http-* script IDs when nmap misnames the service (HTB Unified's 8443)", () => {
    const scripts = JSON.stringify([
      { id: "ssl-cert", output: "Subject: commonName=UniFi/..." },
      { id: "http-title", output: "UniFi Network" },
      { id: "ssl-date", output: "TLS randomness does not represent time" },
    ]);
    expect(isHttpLikeService("nagios-nsca", scripts)).toBe(true);
  });

  it("stays false when neither the name nor any script suggests HTTP", () => {
    const scripts = JSON.stringify([{ id: "ssl-cert", output: "..." }]);
    expect(isHttpLikeService("nagios-nsca", scripts)).toBe(false);
    expect(isHttpLikeService("nagios-nsca")).toBe(false);
    expect(isHttpLikeService("nagios-nsca", "not json")).toBe(false);
  });
});

describe("isDnsLikeService", () => {
  it("matches nmap's domain/dns service names case-insensitively", () => {
    expect(isDnsLikeService("domain")).toBe(true);
    expect(isDnsLikeService("DNS")).toBe(true);
    expect(isDnsLikeService("http")).toBe(false);
  });
});

describe("service investigation summary", () => {
  it("keeps scan observations and names unconfirmed facts", () => {
    expect(parseScriptObservations(
      '[{"id":"telnet-ntlm-info","output":"Target_Name: LAB"}]',
    )).toEqual([{ id: "telnet-ntlm-info", output: "Target_Name: LAB" }]);
    expect(missingServiceFacts({
      name: "telnet",
      product: "Linux telnetd",
      version: "",
      extra_info: "",
      scripts: "[]",
    })).toEqual(["정확한 버전", "추가 배너 정보"]);
  });

  it("builds safe follow-up probes for any protocol catalog", () => {
    const ranked = rankInvestigationCommands("정확한 버전", [
      { id: "ftp-default-audit", name: "FTP 점검", risk: "high", execution_mode: "captured" },
      { id: "ftp-syst", name: "FTP 시스템 정보", risk: "low", execution_mode: "captured" },
      { id: "service-version", name: "제품 버전", risk: "low", execution_mode: "captured" },
      { id: "ftp-client", name: "FTP 접속", risk: "low", execution_mode: "interactive" },
    ]);
    expect(ranked.map((item) => item.id)).toEqual([
      "service-version",
      "ftp-syst",
    ]);
  });

  it("removes confirmed commands from the unified investigation list", () => {
    const commands = [
      { id: "target-hostname-identity", name: "Hostname", risk: "low", execution_mode: "captured" },
      { id: "service-version", name: "제품·버전 식별", risk: "low", execution_mode: "captured" },
      { id: "ftp-syst", name: "FTP 시스템 정보", risk: "low", execution_mode: "captured" },
      { id: "ftp-client", name: "FTP 수동 접속", risk: "low", execution_mode: "interactive" },
    ];
    expect(remainingInvestigationCommands(commands, {
      hostname: "target.htb",
      osGuess: "",
      product: "vsftpd",
      version: "3.0.3",
      completedTemplateIds: new Set(["ftp-syst"]),
    }).map((item) => item.id)).toEqual(["ftp-client"]);
  });

  it("keeps the selected SMB service after a service list refresh", () => {
    const services = [{id: 1}, {id: 2}, {id: 3}];
    expect(keepSelectedService(3, services)).toBe(3);
    expect(keepSelectedService(9, services)).toBe(1);
  });

  it("does not present an empty or wrong-port SMB run as a finding", () => {
    expect(summarizeExecutionResult(
      "smb-enum", "completed", "135/tcp open msrpc", "", "nmap -p135 host",
    ).tone).toBe("danger");
    expect(summarizeExecutionResult(
      "smb-enum", "completed", "445/tcp open microsoft-ds", "", "nmap -p445 host",
    )).toMatchObject({
      tone: "warning",
      title: "공유 목록이 반환되지 않았습니다",
    });
    expect(summarizeExecutionResult(
      "smb-enum", "completed", `
        Sharename       Type      Comment
        ADMIN$          Disk      Remote Admin
      `, "",
      "smbclient -N -L //host -p 445",
    ).tone).toBe("success");
    expect(summarizeExecutionResult(
      "smb-null-session", "completed", "user:[alice] rid:[0x3e8]", "",
      "rpcclient -N host -c enumdomusers",
    ).tone).toBe("success");
  });

  it("turns smbclient output into connectable share rows", () => {
    const output = `
      Sharename       Type      Comment
      ---------       ----      -------
      ADMIN$          Disk      Remote Admin
      IPC$            IPC       Remote IPC
      WorkShares      Disk      Team files
      Reconnecting with SMB1 for workgroup listing.
      Unable to connect with SMB1 -- no workgroup available
    `;
    expect(parseSmbShares(output)).toEqual([
      {name: "ADMIN$", type: "Disk", comment: "Remote Admin"},
      {name: "IPC$", type: "IPC", comment: "Remote IPC"},
      {name: "WorkShares", type: "Disk", comment: "Team files"},
    ]);
    expect(summarizeExecutionResult(
      "smb-enum", "completed", output,
      "NT_STATUS_RESOURCE_NAME_NOT_FOUND", "smbclient -p 445",
    )).toMatchObject({
      tone: "success",
      title: "SMB 공유 목록을 가져왔습니다",
    });
  });

  it("extracts per-share anonymous/current-user access from nmap smb-enum-shares", () => {
    const output = `
Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\\\10.10.10.10\\ADMIN$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\\Windows
|     Anonymous access: <none>
|     Current user access: <none>
|   \\\\10.10.10.10\\backups:
|     Type: STYPE_DISKTREE
|     Comment:
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\\backups
|     Anonymous access: READ
|     Current user access: READ/WRITE
|   \\\\10.10.10.10\\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|_    Anonymous access: READ
    `;
    expect(parseSmbEnumSharesAccess(output)).toEqual({
      "ADMIN$": {anonymous: "<none>", currentUser: "<none>"},
      "backups": {anonymous: "READ", currentUser: "READ/WRITE"},
      "IPC$": {anonymous: "READ", currentUser: ""},
    });
  });

  it("returns an empty map when smb-enum-shares hasn't been run", () => {
    expect(parseSmbEnumSharesAccess("")).toEqual({});
    expect(parseSmbEnumSharesAccess("some unrelated nmap output\n")).toEqual({});
  });

  it("flattens recursive smbclient listings into file paths, skipping dirs", () => {
    const output =
      "  .                                   D        0  Mon Mar 29 04:22:01 2021\n" +
      "  ..                                  D        0  Mon Mar 29 04:22:01 2021\n" +
      "  Amy.J                               D        0  Mon Mar 29 05:08:24 2021\n" +
      "  James.P                             D        0  Thu Jun  3 04:38:03 2021\n" +
      "\n" +
      "\\Amy.J\n" +
      "  .                                   D        0  Mon Mar 29 05:08:24 2021\n" +
      "  ..                                  D        0  Mon Mar 29 05:08:24 2021\n" +
      "  worknotes.txt                       A       94  Fri Mar 26 07:00:37 2021\n" +
      "\n" +
      "\\James.P\n" +
      "  .                                   D        0  Thu Jun  3 04:38:03 2021\n" +
      "  ..                                  D        0  Thu Jun  3 04:38:03 2021\n" +
      "  flag.txt                            A       32  Mon Mar 29 05:26:57 2021\n";
    expect(parseSmbFiles(output)).toEqual([
      {path: "Amy.J/worknotes.txt", size: "94"},
      {path: "James.P/flag.txt", size: "32"},
    ]);
  });

  it("keeps only response entries from feroxbuster --json output", () => {
    const output =
      '{"type":"response","url":"http://h/config.txt","original_url":"http://h/",' +
      '"path":"/config.txt","wildcard":false,"status":200,"method":"GET",' +
      '"content_length":12,"line_count":1,"word_count":2,"headers":{},' +
      '"extension":"","truncated":false,"timestamp":1}\n' +
      '{"type":"statistics","expected_per_second":100}\n' +
      '{"type":"response","url":"http://h/secret.php","original_url":"http://h/",' +
      '"path":"/secret.php","wildcard":false,"status":403,"method":"GET",' +
      '"content_length":0,"line_count":0,"word_count":0,"headers":{},' +
      '"extension":"","truncated":false,"timestamp":2}\n';
    expect(parseFeroxbusterResults(output)).toEqual([
      {path: "/config.txt", status: 200, length: 12, words: 2, lines: 1},
      {path: "/secret.php", status: 403, length: 0, words: 0, lines: 0},
    ]);
  });

  it("extracts only VALID USERNAME lines from kerbrute output", () => {
    const output = [
      "2026/08/02 12:00:00 >  Using KDC(s):",
      "2026/08/02 12:00:00 >  \t10.10.10.10:88",
      "2026/08/02 12:00:01 >  [+] VALID USERNAME:\t administrator@CORP.LOCAL",
      "2026/08/02 12:00:02 >  [-] CORP.LOCAL\\guest:",
      "2026/08/02 12:00:03 >  [+] VALID USERNAME:\t svc-sql@CORP.LOCAL",
      "2026/08/02 12:00:04 >  Done enumerating",
    ].join("\n");
    expect(parseKerbruteResults(output)).toEqual([
      "administrator@CORP.LOCAL", "svc-sql@CORP.LOCAL",
    ]);
  });

  it("returns no usernames from output with no matches", () => {
    expect(parseKerbruteResults("Using KDC(s):\n\t10.10.10.10:88\n")).toEqual([]);
  });

  it("extracts hostname/status/size from ffuf's default vhost output", () => {
    const output = [
      "",
      "       /'___\\  /'___\\           /'___\\       ",
      ":: Progress: [5000/5000] :: Job [1/1] :: 200 req/sec",
      "",
      "admin                   [Status: 200, Size: 1543, Words: 120, Lines: 40, Duration: 45ms]",
      "wiki                    [Status: 200, Size: 8821, Words: 900, Lines: 210, Duration: 51ms]",
      ":: Progress: [5000/5000] :: Job [1/1] :: 200 req/sec :: Errors: 0 ::",
    ].join("\n");
    expect(parseFfufVhostResults(output)).toEqual([
      { name: "admin", status: 200, size: 1543 },
      { name: "wiki", status: 200, size: 8821 },
    ]);
  });

  it("returns no vhost results from output with no matches", () => {
    expect(parseFfufVhostResults(":: Progress: [0/5000] ::\n")).toEqual([]);
  });

  it("extracts subdomains and resolved IPs from a gobuster dns -i run", () => {
    const output = [
      "Found: admin.corp.local [10.10.11.5]",
      "Found: vpn.corp.local",
      "Progress: 4995 / 5000 (99.90%)",
    ].join("\n");
    expect(parseGobusterDnsResults(output)).toEqual([
      { name: "admin.corp.local", ip: "10.10.11.5" },
      { name: "vpn.corp.local", ip: undefined },
    ]);
  });

  it("returns no dns results from output with no matches", () => {
    expect(parseGobusterDnsResults("Progress: 0 / 5000 (0.00%)\n")).toEqual([]);
  });

  it("extracts only [+] hit lines from a netexec spray run", () => {
    const output = [
      "LDAP        10.10.10.161   389    FOREST           [*] Windows Server 2016",
      "LDAP        10.10.10.161   389    FOREST           [-] htb.local\\andy:Fall2018!",
      "LDAP        10.10.10.161   389    FOREST           [+] htb.local\\sebastien:s3bastien1",
      "LDAP        10.10.10.161   389    FOREST           [-] htb.local\\mark:Fall2018!",
    ].join("\n");
    expect(parseNetexecSprayHits(output)).toEqual(["htb.local\\sebastien:s3bastien1"]);
  });

  it("returns no hits from a spray run with no valid credentials", () => {
    expect(parseNetexecSprayHits(
      "LDAP  10.10.10.161  389  FOREST  [-] htb.local\\andy:Fall2018!\n",
    )).toEqual([]);
  });

  it("extracts user:rid:lmhash:nthash lines from a secretsdump DCSync run", () => {
    const output = [
      "Impacket v0.11.0 - Copyright 2023 Fortra",
      "[*] Using the DRSUAPI method to get NTDS.DIT secrets",
      "Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::",
      "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefaf12a68b57f6660c83cf43d:::",
      "htb.local\\svc-alfresco:1104:aad3b435b51404eeaad3b435b51404ee:9deb5a092a9baf843c8f2726a1a12b8b:::",
      "[*] Kerberos keys grabbed",
      "Administrator:aes256-cts-hmac-sha1-96:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ].join("\n");
    expect(parseSecretsdumpHashes(output)).toEqual([
      { username: "Administrator", rid: "500", lmhash: "aad3b435b51404eeaad3b435b51404ee",
        nthash: "32693b11e6aa90eb43d32c72a07ceea6" },
      { username: "krbtgt", rid: "502", lmhash: "aad3b435b51404eeaad3b435b51404ee",
        nthash: "1693c6cefaf12a68b57f6660c83cf43d" },
      { username: "htb.local\\svc-alfresco", rid: "1104",
        lmhash: "aad3b435b51404eeaad3b435b51404ee", nthash: "9deb5a092a9baf843c8f2726a1a12b8b" },
    ]);
  });

  it("returns no hashes when DCSync failed or was denied", () => {
    expect(parseSecretsdumpHashes(
      "[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied\n",
    )).toEqual([]);
  });
});
