// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import NetexecOutcome from "./NetexecOutcome";

afterEach(cleanup);

const actions = {openPsexec: vi.fn(), openLateral: vi.fn(), openSsh: vi.fn(),
  openWinrm: vi.fn(), copyRdp: vi.fn(), openMssql: vi.fn(), openHashcat: vi.fn(),
  openLookupsid: vi.fn(), captureEvidence: vi.fn(), promoteFinding: vi.fn()};

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
