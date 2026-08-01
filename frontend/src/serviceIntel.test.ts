import { describe, expect, it } from "vitest";
import {
  keepSelectedService,
  missingServiceFacts,
  parseFeroxbusterResults,
  parseSmbFiles,
  parseSmbShares,
  parseScriptObservations,
  rankInvestigationCommands,
  remainingInvestigationCommands,
  summarizeExecutionResult,
} from "./serviceIntel";

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
});
