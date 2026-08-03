// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import PasswordSprayPanel from "./PasswordSprayPanel";

afterEach(cleanup);

const target = { ip: "10.10.10.161" };

it("starts the spray with the typed usersfile and password, disabled until both are filled", () => {
  const onSpray = vi.fn();
  render(<PasswordSprayPanel target={target} serviceExecutions={[]} evidenceMsg=""
    onSpray={onSpray} onCaptureEvidence={vi.fn()} />);

  const button = screen.getByText("스프레이 시작") as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("사용자명 목록 파일 경로"), {
    target: { value: "/tmp/users.txt" },
  });
  fireEvent.change(screen.getByLabelText("비밀번호"), { target: { value: "Fall2018!" } });
  expect(button.disabled).toBe(false);
  fireEvent.click(button);

  expect(onSpray).toHaveBeenCalledWith("/tmp/users.txt", "Fall2018!");
});

it("shows the account-lockout warning up front", () => {
  render(<PasswordSprayPanel target={target} serviceExecutions={[]} evidenceMsg=""
    onSpray={vi.fn()} onCaptureEvidence={vi.fn()} />);
  expect(screen.getByText(/계정 잠금 정책/)).toBeTruthy();
});

it("fills the usersfile field from a recently derived wordlist on click", () => {
  render(<PasswordSprayPanel target={target} serviceExecutions={[]} evidenceMsg=""
    wordlistSuggestion="/home/kali/OSCP-Workspace/projects/Forest/targets/10.10.10.161/outputs/users.txt"
    onSpray={vi.fn()} onCaptureEvidence={vi.fn()} />);

  fireEvent.click(screen.getByText("방금 저장한 목록 사용 (users.txt)"));

  expect((screen.getByLabelText("사용자명 목록 파일 경로") as HTMLInputElement).value)
    .toBe("/home/kali/OSCP-Workspace/projects/Forest/targets/10.10.10.161/outputs/users.txt");
});

it("parses [+] hit lines from the live run and offers to capture them as evidence", () => {
  const onCaptureEvidence = vi.fn();
  const stdout = [
    "LDAP  10.10.10.161  389  FOREST  [-] htb.local\\andy:Fall2018!",
    "LDAP  10.10.10.161  389  FOREST  [+] htb.local\\sebastien:s3bastien1",
  ].join("\n");
  render(<PasswordSprayPanel target={target}
    serviceExecutions={[{ id: 3, template_id: "ad-password-spray-netexec",
      status: "completed", stdout: "stale" }]}
    runState={{ id: 4, templateId: "ad-password-spray-netexec", status: "completed", stdout }}
    evidenceMsg="" onSpray={vi.fn()} onCaptureEvidence={onCaptureEvidence} />);

  expect(screen.getByText("htb.local\\sebastien:s3bastien1")).toBeTruthy();
  expect(screen.getByText("1개")).toBeTruthy();
  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledWith(
    { id: 4, stdout, stderr: undefined },
    `패스워드 스프레이 유효 자격증명 · ${target.ip}`,
  );
});
