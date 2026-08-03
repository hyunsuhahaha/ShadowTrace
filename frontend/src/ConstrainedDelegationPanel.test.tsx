// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import ConstrainedDelegationPanel from "./ConstrainedDelegationPanel";

afterEach(cleanup);

const target = { ip: "10.10.10.248" };

it("requests a delegation ticket with the typed fields, disabled until all are filled", () => {
  const onRequest = vi.fn();
  render(<ConstrainedDelegationPanel target={target} serviceExecutions={[]} evidenceMsg=""
    onRequest={onRequest} onCaptureEvidence={vi.fn()} />);

  const button = screen.getByText("위임 티켓 요청") as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("SPN"), {
    target: { value: "cifs/dc01.intelligence.htb" } });
  fireEvent.change(screen.getByLabelText("도메인"), { target: { value: "intelligence.htb" } });
  fireEvent.change(screen.getByLabelText("위임 계정 사용자명"), { target: { value: "svc_int$" } });
  fireEvent.change(screen.getByLabelText("위임 계정 비밀번호"), {
    target: { value: "aa07d7ff70386dfe0ae54c1de92b26e5" } });
  expect(button.disabled).toBe(false);

  fireEvent.click(button);
  expect(onRequest).toHaveBeenCalledWith({
    spn: "cifs/dc01.intelligence.htb", targetUsername: "administrator",
    domain: "intelligence.htb", username: "svc_int$",
    password: "aa07d7ff70386dfe0ae54c1de92b26e5",
  });
});

it("shows the saved ccache path and a ready KRB5CCNAME hint once the run completes", () => {
  const { container } = render(<ConstrainedDelegationPanel target={target} evidenceMsg=""
    serviceExecutions={[{
      id: 11, template_id: "ad-constrained-delegation-getst", status: "completed",
      stdout: "[*] Saving ticket in administrator.ccache\n",
    }]}
    onRequest={vi.fn()} onCaptureEvidence={vi.fn()} />);

  expect(container.textContent).toContain("티켓 저장됨: administrator.ccache");
  expect(container.textContent).toContain("KRB5CCNAME=administrator.ccache");
});

it("captures the run as evidence", () => {
  const onCaptureEvidence = vi.fn();
  render(<ConstrainedDelegationPanel target={target} evidenceMsg=""
    serviceExecutions={[{
      id: 11, template_id: "ad-constrained-delegation-getst", status: "completed",
      stdout: "[*] Saving ticket in administrator.ccache\n",
    }]}
    onRequest={vi.fn()} onCaptureEvidence={onCaptureEvidence} />);

  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledOnce();
});
