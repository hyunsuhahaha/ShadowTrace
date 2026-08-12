// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen, waitFor} from "@testing-library/react";
import {afterEach, expect, test, vi} from "vitest";
import {api} from "./api";
import FloatingCommandSession from "./FloatingCommandSession";

vi.mock("./api", () => ({api: vi.fn()}));
vi.mock("./PtyTerminal", () => ({default: ({sessionId, initialInput}: {
  sessionId: number; initialInput?: string;
}) => <div data-testid="pty">{sessionId}:{initialInput}</div>}));

afterEach(() => {
  cleanup();
  vi.mocked(api).mockReset();
});

test("전체 실행 명령을 출력 위에 표시한다", () => {
  const command = "nmap -Pn -sV --version-all --host-timeout 120s 10.129.95.174";
  render(<FloatingCommandSession executedCommand={command}>
    <pre>scan output</pre>
  </FloatingCommandSession>);

  expect(screen.getByText(command)).toBeTruthy();
  expect(screen.queryByLabelText("플로팅 터미널 명령")).toBeNull();
});

test("하단 명령을 target-bound Bash PTY에 전달한다", async () => {
  vi.mocked(api).mockResolvedValue({id: 77});
  render(<FloatingCommandSession context={{
    targetId: 4, targetIp: "10.129.95.174", serviceId: 12,
  }}><pre>scan output</pre></FloatingCommandSession>);

  fireEvent.change(screen.getByLabelText("플로팅 터미널 명령"), {
    target: {value: "whoami"},
  });
  fireEvent.submit(screen.getByRole("button", {name: "PTY ↵"}).closest("form")!);

  await waitFor(() => expect(api).toHaveBeenCalledWith("/interactive-sessions/manual", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({target_id: 4, service_id: 12}),
  }));
  expect((await screen.findByTestId("pty")).textContent).toBe("77:whoami\r");
});
