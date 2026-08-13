// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { Inspector } from "./Inspector";

vi.mock("../../XtermOutput", () => ({default: ({output}: {output: string}) =>
  <pre aria-label="Responder 세션 로그">{output}</pre>}));
vi.mock("../../InteractiveTerminal", () => ({default: ({sessionId}: {sessionId: number}) =>
  <div>PTY #{sessionId}</div>}));

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});

it("offers the full link-extract workflow from an execution node", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/executions/42/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "css/style.css\nhttps://cdn.example/app.js\n/index.php?page=german.html\n",
      stderr: "", status: "completed", error: "", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      { id: 10, project_id: 3, ip: "10.10.11.80", hostname: "unika.htb" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets/10/services")) return Promise.resolve(new Response(JSON.stringify([
      { id: 20, port: 80, name: "http", tls: false },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/executions/42/derive") && init?.method === "POST")
      return Promise.resolve(new Response(JSON.stringify({ id: 7 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  const openRequest = vi.fn();
  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10, serviceId: 20 }} node={{
      id: "tech-1", type: "technique", status: "succeeded",
      label: "웹 링크 추출", objective: false, hidden: false,
      meta: JSON.stringify({ tool: "http-link-extract" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 42 }),
    }} busy={false} onOpenRequest={openRequest}
      onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  await screen.findByText("/index.php?page=german.html");
  const result = screen.getByLabelText("링크 추출 결과");
  expect(result.textContent?.indexOf("/index.php?page=german.html"))
    .toBeLessThan(result.textContent?.indexOf("https://cdn.example/app.js") ?? 0);
  expect(result.textContent?.indexOf("https://cdn.example/app.js"))
    .toBeLessThan(result.textContent?.indexOf("css/style.css") ?? 0);

  const requestButtons = screen.getAllByText("Request 탭에 채우기");
  expect(requestButtons).toHaveLength(2);
  location.hash = "#graph";
  fireEvent.click(requestButtons[0]);
  expect(JSON.parse(localStorage.getItem("oscp-web-launch") || "null")).toEqual({
    targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=german.html",
  });
  expect(location.hash).toBe("#graph");
  expect(openRequest).toHaveBeenCalledWith({ projectId: 3, targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=german.html" });

  fireEvent.click(screen.getByText("Evidence로 저장"));
  await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
    "/api/executions/42/derive", expect.objectContaining({ method: "POST" }),
  ));
  expect(await screen.findByText("Evidence로 저장됨")).toBeTruthy();
});

it("shows service context and logs for every execution node", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    const body = url.endsWith("/api/executions/77/output") ? {
      stdout: "HTTPServer[Microsoft-HTTPAPI/2.0]", stderr: "probe timed out once",
      status: "failed", error: "timeout", exit_code: 1,
    } : url.endsWith("/api/targets") ? [
      { id: 10, ip: "10.129.95.234" },
    ] : url.endsWith("/api/targets/10/services") ? [
      { id: 20, port: 5985, name: "http", product: "Microsoft HTTPAPI httpd", tls: false },
    ] : null;
    if (body === null) throw new Error(`Unhandled request: ${url}`);
    return Promise.resolve(new Response(JSON.stringify(body), {
      headers: { "Content-Type": "application/json" },
    }));
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10, serviceId: 20 }} node={{
      id: "tech-2", type: "technique", status: "attempt-failed",
      label: "http-whatweb", objective: false, hidden: false,
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 77 }),
      meta: JSON.stringify({ command: "whatweb http://10.129.95.234:5985" }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  // Target/service context now lives in the terminal-style title bar as one
  // compact line instead of a separate fact grid.
  expect(await screen.findByText("10.129.95.234:5985 — http-whatweb")).toBeTruthy();
  expect(screen.getByText(/whatweb http:\/\/10\.129\.95\.234:5985/)).toBeTruthy();
  expect(screen.getByText("HTTPServer[Microsoft-HTTPAPI/2.0]")).toBeTruthy();
  expect(screen.getByText("probe timed out once")).toBeTruthy();
  expect(screen.getByText(/exit 1/)).toBeTruthy();
});

it("shows captured credentials for a responder session node", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    const body = url.endsWith("/api/targets") ? [
      { id: 10, project_id: 3, ip: "10.129.95.234" },
    ] : url.endsWith("/api/interactive-sessions?target_id=10") ? [{
      id: 9, command: "sudo responder -I tun0 -v", status: "running",
    }] : url.endsWith("/api/targets/10/responder-captures") ? [{
      label: "SMB-NTLMv2-SSP", username: "Administrator",
      value: "Administrator::RESPONDER:challenge:response", cleartext: false,
      captured_at: "2026-08-09T14:00:00Z",
    }] : null;
    if (url.endsWith("/api/interactive-sessions/9/log"))
      return Promise.resolve(new Response("[+] Listening for events..."));
    if (body === null) throw new Error(`Unhandled request: ${url}`);
    return Promise.resolve(new Response(JSON.stringify(body), {
      headers: { "Content-Type": "application/json" },
    }));
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10 }} node={{
      id: "session-1", type: "technique", status: "in-progress",
      label: "Responder 리스너", objective: false, hidden: false,
      meta: JSON.stringify({ tool: "responder-listener" }),
      source_ref: JSON.stringify({ module: "sessions", kind: "session", id: 9 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("Administrator")).toBeTruthy();
  expect(screen.getByText("NETNTLMv2")).toBeTruthy();
  expect(screen.getByText("해시 보기")).toBeTruthy();
  expect(screen.getByText("Credential 저장")).toBeTruthy();
  expect(await screen.findByText("[+] Listening for events...")).toBeTruthy();
});

it("restarts a failed responder session from its node", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      {id: 10, project_id: 3, ip: "10.129.4.83"},
    ]), {headers: {"Content-Type": "application/json"}}));
    if (url.endsWith("/api/interactive-sessions?target_id=10"))
      return Promise.resolve(new Response(JSON.stringify([
        {id: 19, command: "sudo responder -I tun0 -v", status: "failed"},
      ]), {headers: {"Content-Type": "application/json"}}));
    if (url.endsWith("/api/targets/10/responder-captures"))
      return Promise.resolve(new Response("[]", {headers: {"Content-Type": "application/json"}}));
    if (url.endsWith("/api/interactive-sessions/19/log")) return Promise.resolve(new Response("failed"));
    if (url.endsWith("/api/interactive-sessions/19/retry") && init?.method === "POST")
      return Promise.resolve(new Response(JSON.stringify({
        id: 20, command: "sudo responder -I tun0 -v",
      }), {status: 201, headers: {"Content-Type": "application/json"}}));
    throw new Error(`Unhandled request: ${url}`);
  }));
  const client = new QueryClient({defaultOptions: {queries: {retry: false}}});
  render(<QueryClientProvider client={client}><Inspector executionContext={{targetId: 10}} node={{
    id: "session-19", type: "technique", status: "attempt-failed",
    label: "Responder 리스너", objective: false, hidden: false,
    meta: JSON.stringify({tool: "responder-listener"}),
    source_ref: JSON.stringify({module: "sessions", kind: "session", id: 19}),
  }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  fireEvent.click(await screen.findByText("Responder 다시 시작"));
  expect(await screen.findByText("PTY #20")).toBeTruthy();
});

it("makes a cracked credential and its plaintext directly inspectable", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    if (!String(input).includes("/api/runbooks/credentials?project_id=3"))
      throw new Error(`Unhandled request: ${String(input)}`);
    return Promise.resolve(new Response(JSON.stringify([{
      id: 12, username: "Administrator", domain: "", secret: "badminton",
      secret_kind: "password", secret_hint: "Cracked from NetNTLMv2",
      source_kind: "responder", source_detail: "SMB-NTLMv2-SSP",
      source_execution_kind: "hash_crack_job",
    }]), { headers: { "Content-Type": "application/json" } }));
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector projectId={3} node={{
      id: "credential-12", type: "credential", status: "succeeded",
      label: "Administrator", objective: false, hidden: false,
      meta: JSON.stringify({ username: "Administrator", credType: "password",
        sourceExecutionKind: "hash_crack_job" }),
      source_ref: JSON.stringify({ module: "core", kind: "credential", id: 12 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("크래킹 완료 · 평문 사용 가능")).toBeTruthy();
  fireEvent.click(screen.getByText("평문 보기"));
  expect(screen.getByText("badminton")).toBeTruthy();
  expect(screen.getByText("SMB-NTLMv2-SSP")).toBeTruthy();
});

it("restores a NetExec outcome and the latest saved file tree on its graph node", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    const body = url.endsWith("/api/executions/88/output") ? {
      stdout: "[+] WINRM 10.129.4.83 Administrator:badminton (Pwn3d!)",
      stderr: "", status: "completed", exit_code: 0,
    } : url.endsWith("/api/targets") ? [
      { id: 10, project_id: 3, ip: "10.129.4.83" },
    ] : url.endsWith("/api/targets/10/services") ? [
      { id: 20, port: 5985, name: "winrm" },
    ] : url.endsWith("/api/post-exploitation?target_id=10") ? [
      { id: 51, command_id: "windows_file_tree_winrm", category: "file_tree",
        status: "completed", created_at: "2026-08-13T15:00:00Z" },
    ] : url.endsWith("/api/post-exploitation/51/output") ? {
      stdout: "D|C:\\\nD|C:\\Users\nF|C:\\Users\\Administrator\\flag.txt\n", stderr: "",
    } : null;
    if (body === null) throw new Error(`Unhandled request: ${url}`);
    return Promise.resolve(new Response(JSON.stringify(body), {
      headers: { "Content-Type": "application/json" },
    }));
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector projectId={3} executionContext={{ targetId: 10, serviceId: 20 }} node={{
      id: "execution-88", type: "technique", status: "succeeded",
      label: "WinRM 자격증명 확인 (NetExec)", objective: false, hidden: false,
      meta: JSON.stringify({ tool: "winrm-credential-check-netexec",
        command: "nxc winrm 10.129.4.83 --port 5985 -u Administrator -p ***" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 88 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("인증 성공")).toBeTruthy();
  expect(screen.getByText("10.129.4.83:5985")).toBeTruthy();
  expect(await screen.findByText("flag.txt")).toBeTruthy();
  expect(screen.getByText(/저장된 실행 #51/)).toBeTruthy();
});
