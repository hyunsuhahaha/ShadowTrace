// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import NetexecOutcome from "./NetexecOutcome";

afterEach(cleanup);

const actions = {openPsexec: vi.fn(), openLateral: vi.fn(), openSsh: vi.fn(),
  openWinrm: vi.fn(), copyRdp: vi.fn(), openMssql: vi.fn(), openHashcat: vi.fn(),
  openLookupsid: vi.fn(), openMssqlRidBrute: vi.fn(),
  captureEvidence: vi.fn(), promoteFinding: vi.fn()};

it("offers explicit post-auth actions for an SMB admin result", () => {
  render(<NetexecOutcome protocol="smb" username="admin" domain="LAB"
    evidenceMsg="" actions={actions} result={{id: 9, templateId: "smb-check",
      name: "SMB", status: "completed", startedAt: 0, stdout: "[+] Pwn3d!"}} />);
  fireEvent.click(screen.getByText("psexec"));
  expect(actions.openPsexec).toHaveBeenCalledOnce();
  expect(screen.getByText("Evidence로 저장")).toBeTruthy();
});

it("offers SID-cycling enumeration for any successful SMB login, not just local admin", () => {
  render(<NetexecOutcome protocol="smb" username="hazard" domain="WORKGROUP"
    evidenceMsg="" actions={actions} result={{id: 12, templateId: "smb-check",
      name: "SMB", status: "completed", startedAt: 0,
      stdout: "[+] WORKGROUP\\hazard:stealth1agent"}} />);
  fireEvent.click(screen.getByText("SID 순환으로 사용자 열거 (lookupsid)"));
  expect(actions.openLookupsid).toHaveBeenCalledOnce();
});

it("renders the auto file tree inline for a successful WinRM login", () => {
  render(<NetexecOutcome protocol="winrm" username="administrator" domain=""
    evidenceMsg="" actions={actions} result={{id: 20, templateId: "winrm-check",
      name: "WinRM", status: "completed", startedAt: 0,
      stdout: "[+] administrator:P@ssw0rd (Pwn3d!)"}}
    fileTree={{status: "completed", output: "D|Users\nF|Users\\notes.txt\n"}} />);

  expect(screen.getByText("Users").closest("details")).toBeTruthy();
});

it("shows an in-progress label while the auto file tree is still running", () => {
  render(<NetexecOutcome protocol="ssh" username="mike" domain=""
    evidenceMsg="" actions={actions} result={{id: 21, templateId: "ssh-check",
      name: "SSH", status: "completed", startedAt: 0, stdout: "[+] mike:pass123"}}
    fileTree={{status: "running", output: ""}} />);

  expect(screen.getByText(/자동 조회 중/)).toBeTruthy();
});

it("offers RID-brute enumeration for a successful MS SQL login", () => {
  render(<NetexecOutcome protocol="mssql" username="kevin" domain=""
    evidenceMsg="" actions={actions} result={{id: 14, templateId: "mssql-check",
      name: "MSSQL", status: "completed", startedAt: 0,
      stdout: "[+] eighteen.htb\\kevin:iNa2we6haRj2gaw!"}} />);
  fireEvent.click(screen.getByText("RID 순환으로 사용자 열거 (--rid-brute)"));
  expect(actions.openMssqlRidBrute).toHaveBeenCalledOnce();
});
