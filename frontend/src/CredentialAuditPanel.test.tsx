// @vitest-environment jsdom
import {fireEvent, render, screen} from "@testing-library/react";
import {expect, it, vi} from "vitest";
import CredentialAuditPanel from "./CredentialAuditPanel";

const profile = {
  title: "SMB 인증 점검",
  description: "허용된 계정만 확인합니다.",
  identityLabel: "사용자", identities: "users.txt",
  secretLabel: "비밀번호", secrets: "passwords.txt",
  limits: "낮은 시도 횟수를 유지하세요.",
};
const command = {
  id: "smb-default-audit", name: "기본 자격 증명", description: "제한된 점검",
  risk: "high",
};

it("shows audit safety context and forwards review requests", () => {
  const onReview = vi.fn();
  render(<CredentialAuditPanel profile={profile} serviceName="smb"
    commands={[command]} runStates={{}} clock={2000} onReview={onReview} />);

  expect(screen.getByText("SMB 인증 점검")).toBeTruthy();
  expect(screen.getByText("잠금 위험")).toBeTruthy();
  fireEvent.click(screen.getByText("대입 공격 검토·실행"));
  expect(onReview).toHaveBeenCalledWith(command);
});

it("disables a running audit and reports elapsed time", () => {
  render(<CredentialAuditPanel profile={profile} commands={[command]}
    runStates={{[command.id]: {
      templateId: command.id, name: command.name, status: "running", startedAt: 1000,
    }}} clock={4000} onReview={vi.fn()} />);

  const button = screen.getByText("대입 중…") as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  expect(screen.getByText("프로세스 실행 중 · 3초")).toBeTruthy();
});
