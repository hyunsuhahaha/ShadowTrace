// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import CredentialAuditPanel from "./CredentialAuditPanel";

afterEach(() => cleanup());

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
const mysqlProfile = {
  title: "MySQL 대입 후보",
  description: "빈 비밀번호를 먼저 확인합니다.",
  identityLabel: "사용자 후보", identities: "root · mysql · admin",
  secretLabel: "비밀번호 후보", secrets: "빈 값 · root · mysql · password",
  limits: "최대 2분",
};
const probeCommand = {
  id: "mysql-credential-probe", name: "MySQL 기본 자격증명 직접 대입", description: "직접 대입",
  risk: "medium", command: "bash probe.sh {host} {port} {username} {password}",
};

it("marks which command actually uses the edited candidates and which doesn't", () => {
  render(<CredentialAuditPanel profile={mysqlProfile} commands={[probeCommand, command]}
    runStates={{}} clock={0} onReview={vi.fn()} />);

  expect(screen.getByText("↑ 위 후보 사용")).toBeTruthy();
  expect(screen.getByText("고정 검사 (후보 미반영)")).toBeTruthy();
});

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

it("seeds the candidate boxes from the profile and sends them as edited when unchanged", () => {
  const onReview = vi.fn();
  render(<CredentialAuditPanel profile={mysqlProfile} commands={[probeCommand]}
    runStates={{}} clock={0} onReview={onReview} />);

  fireEvent.click(screen.getByText("대입 공격 검토·실행"));

  expect(onReview).toHaveBeenCalledWith({
    ...probeCommand,
    variables: {username: "root,mysql,admin", password: ",root,mysql,password"},
  });
});

it("sends edited candidates, turning the blank-password token into an empty string", () => {
  const onReview = vi.fn();
  render(<CredentialAuditPanel profile={mysqlProfile} commands={[probeCommand]}
    runStates={{}} clock={0} onReview={onReview} />);

  fireEvent.change(screen.getByPlaceholderText("한 줄에 하나씩"),
    {target: {value: "svc\ndba"}});
  fireEvent.change(screen.getByPlaceholderText(/빈 비밀번호는/),
    {target: {value: "toor\n빈 값"}});
  fireEvent.click(screen.getByText("대입 공격 검토·실행"));

  expect(onReview).toHaveBeenCalledWith({
    ...probeCommand,
    variables: {username: "svc,dba", password: "toor,"},
  });
});

it("does not attach candidate variables to commands whose template has no place for them", () => {
  const onReview = vi.fn();
  render(<CredentialAuditPanel profile={mysqlProfile} commands={[command]}
    runStates={{}} clock={0} onReview={onReview} />);

  fireEvent.click(screen.getByText("대입 공격 검토·실행"));

  expect(onReview).toHaveBeenCalledWith(command);
});

it("blocks running the probe once the candidate combinations exceed the script's cap", () => {
  const onReview = vi.fn();
  render(<CredentialAuditPanel profile={mysqlProfile} commands={[probeCommand]}
    runStates={{}} clock={0} onReview={onReview} />);

  fireEvent.change(screen.getByPlaceholderText("한 줄에 하나씩"), {
    target: {value: Array.from({length: 7}, (_, i) => `user${i}`).join("\n")},
  });
  fireEvent.change(screen.getByPlaceholderText(/빈 비밀번호는/), {
    target: {value: Array.from({length: 7}, (_, i) => `pass${i}`).join("\n")},
  });

  expect(screen.getByText(/스크립트 상한\(40개\)을 초과/)).toBeTruthy();
  expect((screen.getByText("대입 공격 검토·실행") as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByText("대입 공격 검토·실행"));
  expect(onReview).not.toHaveBeenCalled();
});
