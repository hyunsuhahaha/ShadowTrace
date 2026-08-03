// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import SilverTicketPanel from "./SilverTicketPanel";

afterEach(cleanup);

const target = { ip: "10.129.242.173" };

it("forges a ticket with the typed fields, disabled until all are filled", () => {
  const onForge = vi.fn();
  render(<SilverTicketPanel target={target} serviceExecutions={[]} evidenceMsg=""
    onForge={onForge} onCaptureEvidence={vi.fn()} />);

  const button = screen.getByText("Silver Ticket 위조") as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("NTLM 해시"), {
    target: { value: "ef699384c3285c54128a3ee1ddb1a0cc" } });
  fireEvent.change(screen.getByLabelText("도메인"), { target: { value: "signed.htb" } });
  fireEvent.change(screen.getByLabelText("도메인 SID"), {
    target: { value: "S-1-5-21-4088429403-1159899800-2753317549" } });
  fireEvent.change(screen.getByLabelText("SPN"), {
    target: { value: "MSSQLSvc/DC01.signed.htb:1433" } });
  fireEvent.change(screen.getByLabelText("그룹 RID"), { target: { value: "1105" } });
  expect(button.disabled).toBe(false);

  fireEvent.click(button);
  expect(onForge).toHaveBeenCalledWith({
    nthash: "ef699384c3285c54128a3ee1ddb1a0cc", domain: "signed.htb",
    domainSid: "S-1-5-21-4088429403-1159899800-2753317549",
    spn: "MSSQLSvc/DC01.signed.htb:1433", groups: "1105", targetUsername: "Administrator",
  });
});

it("fills the nthash field from a DCSync-dumped account on click", () => {
  render(<SilverTicketPanel target={target} serviceExecutions={[]} evidenceMsg=""
    dcsyncStdout={"signed.htb\\mssqlsvc:1103:aad3b435b51404eeaad3b435b51404ee:" +
      "ef699384c3285c54128a3ee1ddb1a0cc:::\n"}
    onForge={vi.fn()} onCaptureEvidence={vi.fn()} />);

  fireEvent.click(screen.getByText("signed.htb\\mssqlsvc 해시 사용"));

  expect((screen.getByLabelText("NTLM 해시") as HTMLInputElement).value)
    .toBe("ef699384c3285c54128a3ee1ddb1a0cc");
});

it("shows the saved ccache path and a ready KRB5CCNAME hint once the run completes", () => {
  const { container } = render(<SilverTicketPanel target={target} evidenceMsg=""
    serviceExecutions={[{
      id: 9, template_id: "ad-silver-ticket-ticketer", status: "completed",
      stdout: "[*] Saving ticket in Administrator.ccache\n",
    }]}
    onForge={vi.fn()} onCaptureEvidence={vi.fn()} />);

  expect(container.textContent).toContain("티켓 저장됨: Administrator.ccache");
  expect(container.textContent).toContain("KRB5CCNAME=Administrator.ccache");
});

it("captures the run as evidence", () => {
  const onCaptureEvidence = vi.fn();
  render(<SilverTicketPanel target={target} evidenceMsg=""
    serviceExecutions={[{
      id: 9, template_id: "ad-silver-ticket-ticketer", status: "completed",
      stdout: "[*] Saving ticket in Administrator.ccache\n",
    }]}
    onForge={vi.fn()} onCaptureEvidence={onCaptureEvidence} />);

  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledOnce();
});
