// @vitest-environment jsdom
import {fireEvent, render, screen} from "@testing-library/react";
import {expect, it, vi} from "vitest";
import NetexecOutcome from "./NetexecOutcome";

const actions = {openPsexec: vi.fn(), openLateral: vi.fn(), openSsh: vi.fn(),
  openWinrm: vi.fn(), copyRdp: vi.fn(), openMssql: vi.fn(), openHashcat: vi.fn(),
  captureEvidence: vi.fn(), promoteFinding: vi.fn()};

it("offers explicit post-auth actions for an SMB admin result", () => {
  render(<NetexecOutcome protocol="smb" username="admin" domain="LAB"
    evidenceMsg="" actions={actions} result={{id: 9, templateId: "smb-check",
      name: "SMB", status: "completed", startedAt: 0, stdout: "[+] Pwn3d!"}} />);
  fireEvent.click(screen.getByText("psexec"));
  expect(actions.openPsexec).toHaveBeenCalledOnce();
  expect(screen.getByText("Evidence로 저장")).toBeTruthy();
});
