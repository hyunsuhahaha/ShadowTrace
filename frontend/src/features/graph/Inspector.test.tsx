// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { Inspector } from "./Inspector";
import { FILE_DRAG_MIME } from "../../fileTree";

vi.mock("../../XtermOutput", () => ({default: ({output}: {output: string}) =>
  <pre aria-label="Responder 세션 로그">{output}</pre>}));
vi.mock("../../InteractiveTerminal", () => ({default: ({sessionId, inputRequest}:
  {sessionId: number; inputRequest?: {data: string}}) =>
  <div>PTY #{sessionId}
    {inputRequest && <span> · 전송: {inputRequest.data}</span>}
    {inputRequest && <span data-testid="raw-input-request" data-command={inputRequest.data} />}
  </div>}));

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});

it("shows a memo node as a freeform note instead of a domain finding/technique", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    throw new Error(`Unhandled request: ${String(input)}`);
  }));
  const onSetStatus = vi.fn();
  const onSetDetails = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "note-1", type: "memo", status: "untried", objective: false, hidden: false,
      label: "새 메모", notes: "admin:hunter2", source_ref: "",
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={onSetStatus} onAddNode={vi.fn()}
      onSetDetails={onSetDetails} />
  </QueryClientProvider>);

  // no 상태 buttons -- untried/in-progress/... doesn't mean anything for a note
  expect(screen.queryByText("준비됨")).toBeNull();
  expect(screen.queryByText("완료")).toBeNull();

  const title = await screen.findByPlaceholderText("메모 제목");
  expect((title as HTMLInputElement).value).toBe("새 메모");
  fireEvent.change(title, { target: { value: "발견한 자격증명" } });
  fireEvent.blur(title);
  expect(onSetDetails).toHaveBeenCalledWith("note-1", { label: "발견한 자격증명" });

  expect(screen.getByText("메모 내용")).toBeTruthy();
  const body = screen.getByPlaceholderText("자유롭게 기록하세요 -- txt 파일처럼 쓰시면 됩니다.");
  expect((body as HTMLTextAreaElement).value).toBe("admin:hunter2");
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

it("offers to try a cracked credential's plaintext over SSH -- Unified's mongo-dump password reuse never had this action", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("/api/runbooks/credentials?project_id=3"))
      return Promise.resolve(new Response(JSON.stringify([{
        id: 12, username: "root", domain: "", secret: "unifi123",
        secret_kind: "password", secret_hint: "MongoDB ace.admin bcrypt cracked",
        source_kind: "hash_crack_job", source_detail: "hashcat bcrypt",
        source_execution_kind: "hash_crack_job",
      }]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets"))
      return Promise.resolve(new Response(JSON.stringify([
        { id: 10, project_id: 3, ip: "10.129.4.83" },
      ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/manual") && init?.method === "POST")
      return Promise.resolve(new Response(JSON.stringify({
        id: 77, command: "ssh root@10.129.4.83",
      }), { status: 201, headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector projectId={3} executionContext={{ targetId: 10 }} node={{
      id: "credential-12", type: "credential", status: "succeeded",
      label: "root", objective: false, hidden: false,
      meta: JSON.stringify({ username: "root", credType: "password",
        sourceExecutionKind: "hash_crack_job" }),
      source_ref: JSON.stringify({ module: "core", kind: "credential", id: 12 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  fireEvent.click(await screen.findByText("SSH로 시도"));
  expect(await screen.findByText("PTY #77")).toBeTruthy();
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

it("offers SSH/MSSQL/RDP connect actions for their own NetExec checks, not just WinRM", async () => {
  // Confirms the graph Inspector's NetExec panel generalized to every
  // protocol NetexecOutcome supports (App.tsx's own copy already did),
  // instead of only ever having WinRM's "evil-winrm 명령 준비하기" wired up.
  const posted: Array<{url: string; body: unknown}> = [];
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/executions/70/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "[+] MSSQL 10.129.7.10 sa:hunter2 (Pwn3d!)", stderr: "", status: "completed", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      { id: 12, project_id: 3, ip: "10.129.7.10" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets/12/services")) return Promise.resolve(new Response(JSON.stringify([
      { id: 22, port: 1433, name: "ms-sql-s" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/manual") && init?.method === "POST") {
      posted.push({url, body: JSON.parse(init.body as string)});
      return Promise.resolve(new Response(JSON.stringify({ id: 77 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 12, serviceId: 22 }} node={{
      id: "execution-70", type: "technique", status: "succeeded",
      label: "MS SQL 자격증명 확인 (NetExec)", objective: false, hidden: false,
      meta: JSON.stringify({ tool: "mssql-credential-check-netexec",
        command: "nxc mssql 10.129.7.10 --port 1433 -u sa -p hunter2" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 70 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("MS SQL 인증 성공")).toBeTruthy();
  fireEvent.click(screen.getByText("impacket-mssqlclient 명령 준비하기"));

  await waitFor(() => expect(posted).toHaveLength(1));
  expect(posted[0].body).toEqual({
    target_id: 12, service_id: 22,
    command: "impacket-mssqlclient 'sa:hunter2@10.129.7.10' -port 1433",
    graph_node_id: "execution-70",
  });
});

it("offers mongosh and shows the auto-fetched db tree once mongodb-info confirms no auth", async () => {
  const posted: Array<{body: unknown}> = [];
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/executions/40/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "| mongodb-info: \n|   MongoDB version: 3.6.8\n", stderr: "", status: "completed", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.includes("/api/executions?target_id=9")) return Promise.resolve(new Response(JSON.stringify([
      { id: 41, template_id: "mongodb-db-tree", service_id: 27, status: "completed",
        stdout: "admin\n  system.users\nloot\n  creds\n" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      { id: 9, project_id: 2, ip: "10.129.8.5" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/manual") && init?.method === "POST") {
      posted.push({body: JSON.parse(init.body as string)});
      return Promise.resolve(new Response(JSON.stringify({ id: 88 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 9, serviceId: 27 }} node={{
      id: "execution-40", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "MongoDB 무인증 정보 확인",
      meta: JSON.stringify({ tool: "mongodb-info" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 40 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText(/admin/)).toBeTruthy();
  fireEvent.click(screen.getByText("mongosh로 접속하기"));

  await waitFor(() => expect(posted).toHaveLength(1));
  expect(posted[0].body).toEqual({
    target_id: 9, service_id: 27, command: "mongosh --host 10.129.8.5 --port 27017",
    graph_node_id: "execution-40",
  });
});

it("shows the auto-fetched OID tree for a confirmed SNMP community string, with no connect action", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/executions/60/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "| snmp-info: \n|   enterprise: net-snmp\n", stderr: "", status: "completed", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.includes("/api/executions?target_id=3")) return Promise.resolve(new Response(JSON.stringify([
      { id: 61, template_id: "snmp-oid-tree", service_id: null, status: "completed",
        stdout: ".1.3.6.1.2.1.1\n  sysDescr\n" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      { id: 3, project_id: 1, ip: "10.129.8.9" },
    ]), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 3 }} node={{
      id: "execution-60", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "SNMP 상세 정보 확인",
      meta: JSON.stringify({ tool: "snmp-info" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 60 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("sysDescr", {exact: false})).toBeTruthy();
  expect(screen.queryByText(/접속하기/)).toBeNull();
});

it("offers to open redis-cli once redis-unauthenticated-info confirms no AUTH is needed", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/executions/15/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "PORT     STATE SERVICE\n6379/tcp open  redis\n| redis-info: \n|   Version: 5.0.7\n"
        + "redis_version:5.0.7\n",
      stderr: "", status: "completed", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      { id: 6, project_id: 7, ip: "10.129.6.199" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets/6/services")) return Promise.resolve(new Response(JSON.stringify([
      { id: 16, port: 6379, name: "redis" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/manual") && init?.method === "POST") {
      expect(JSON.parse(init.body as string)).toEqual({
        target_id: 6, service_id: 16, command: "redis-cli -h 10.129.6.199 -p 6379",
        graph_node_id: "execution-15",
      });
      return Promise.resolve(new Response(JSON.stringify({ id: 99 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 6, serviceId: 16 }} node={{
      id: "execution-15", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "Redis 무인증 접근 확인",
      meta: JSON.stringify({ tool: "redis-unauthenticated-info" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 15 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("인증 없이 접속 가능")).toBeTruthy();
  fireEvent.click(screen.getByText("redis-cli로 접속하기"));

  await waitFor(() => expect(screen.getByText("PTY #99")).toBeTruthy());
});

it("offers a direct download for a finding's attached files instead of only the graph itself", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/findings/11")) return Promise.resolve(new Response(JSON.stringify({
      evidence: [{ id: 15, evidence_id: 124, title: "파일 다운로드: backup.zip",
        kind: "attachment", is_primary: true }],
    }), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "finding-11", type: "finding", status: "untried", objective: false, hidden: false,
      label: "파일 다운로드: backup.zip",
      source_ref: JSON.stringify({ module: "findings", kind: "finding", id: 11 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  const link = await screen.findByText("다운로드");
  expect(link.closest("a")?.getAttribute("href")).toBe("/api/evidence/124/file");
});

it("lets a zip's own contents become graph nodes instead of only offering a raw download", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/findings/11")) return Promise.resolve(new Response(JSON.stringify({
      evidence: [{ id: 15, evidence_id: 124, title: "파일 다운로드: backup.zip",
        kind: "attachment", is_primary: true }],
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/evidence/124/archive")) return Promise.resolve(new Response(JSON.stringify({
      entries: [{ name: "creds.txt", size: 512, encrypted: false }],
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/evidence/124/extract") && init?.method === "POST") {
      expect(JSON.parse(init.body as string)).toEqual(
        { entry: "creds.txt", password: "", graph_node_id: "finding-11" });
      return Promise.resolve(new Response(JSON.stringify({ finding_id: 40, evidence_id: 200 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "finding-11", type: "finding", status: "untried", objective: false, hidden: false,
      label: "파일 다운로드: backup.zip",
      source_ref: JSON.stringify({ module: "findings", kind: "finding", id: 11 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  fireEvent.click(await screen.findByText("압축 해제"));
  fireEvent.click(await screen.findByText("노드로 추가"));

  await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
    "/api/evidence/124/extract", expect.objectContaining({ method: "POST" }),
  ));
  expect(await screen.findByText("추가됨")).toBeTruthy();
});

it("lets a cracked password unlock a password-protected archive member", async () => {
  // Confirmed live: a plaintext recovered via Hash Cracking's zip2john flow
  // used to have nowhere to go back into -- the entry just stayed stuck on
  // "암호 필요" forever with no input for the password that was already known.
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/findings/11")) return Promise.resolve(new Response(JSON.stringify({
      evidence: [{ id: 15, evidence_id: 124, title: "파일 다운로드: protected.zip",
        kind: "attachment", is_primary: true }],
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/evidence/124/archive")) return Promise.resolve(new Response(JSON.stringify({
      entries: [{ name: "secret.txt", size: 12, encrypted: true }],
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/evidence/124/extract") && init?.method === "POST") {
      expect(JSON.parse(init.body as string)).toEqual(
        { entry: "secret.txt", password: "hunter2", graph_node_id: "finding-11" });
      return Promise.resolve(new Response(JSON.stringify({ finding_id: 40, evidence_id: 200 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "finding-11", type: "finding", status: "untried", objective: false, hidden: false,
      label: "파일 다운로드: protected.zip",
      source_ref: JSON.stringify({ module: "findings", kind: "finding", id: 11 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  fireEvent.click(await screen.findByText("압축 해제"));
  const button = await screen.findByText("암호로 해제");
  expect((button as HTMLButtonElement).disabled).toBe(false);

  fireEvent.change(await screen.findByPlaceholderText("크랙한 암호 (암호로 보호된 항목 해제용)"),
    { target: { value: "hunter2" } });
  fireEvent.click(button);

  await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
    "/api/evidence/124/extract", expect.objectContaining({ method: "POST" }),
  ));
  expect(await screen.findByText("추가됨")).toBeTruthy();
});

it("hands a password-protected zip straight to Hash Cracking instead of leaving the operator stuck", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/findings/11")) return Promise.resolve(new Response(JSON.stringify({
      target_id: 8,
      evidence: [{ id: 15, evidence_id: 124, title: "파일 다운로드: protected.zip",
        kind: "attachment", is_primary: true }],
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/evidence/124/archive")) return Promise.resolve(new Response(JSON.stringify({
      entries: [{ name: "secret.txt", size: 12, encrypted: true }],
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/evidence/124/zip2john") && init?.method === "POST") {
      return Promise.resolve(new Response(JSON.stringify({
        hashes: "$pkzip$1*...*$/pkzip$", hash_mode_id: "pkzip",
      }), { headers: { "Content-Type": "application/json" } }));
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const onOpenHashCrack = vi.fn();

  render(<QueryClientProvider client={client}>
    <Inspector projectId={3} node={{
      id: "finding-11", type: "finding", status: "untried", objective: false, hidden: false,
      label: "파일 다운로드: protected.zip",
      source_ref: JSON.stringify({ module: "findings", kind: "finding", id: 11 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()}
      onOpenHashCrack={onOpenHashCrack} />
  </QueryClientProvider>);

  fireEvent.click(await screen.findByText("압축 해제"));
  fireEvent.click(await screen.findByText("🔓 Hash Cracking으로 보내기 (zip2john)"));

  await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
    "/api/evidence/124/zip2john", expect.objectContaining({ method: "POST" }),
  ));
  await waitFor(() => expect(onOpenHashCrack).toHaveBeenCalledWith({
    project_id: 3, target_id: 8, secret: "$pkzip$1*...*$/pkzip$",
    hash_mode_id: "pkzip", source_kind: "zip2john", graph_node_id: "finding-11",
  }));
});

it("shows an extracted text file's content and searches within it instead of the whole page on Ctrl+F", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/findings/11")) return Promise.resolve(new Response(JSON.stringify({
      evidence: [{ id: 15, evidence_id: 124, title: "압축 해제: index.php",
        kind: "attachment", is_primary: true }],
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/evidence/124/preview")) return Promise.resolve(new Response(JSON.stringify({
      content: "admin:hunter2\nguest:guest\nadmin:hunter2again", truncated: false,
    }), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "finding-11", type: "finding", status: "untried", objective: false, hidden: false,
      label: "압축 해제: index.php",
      source_ref: JSON.stringify({ module: "findings", kind: "finding", id: 11 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("guest:guest", { exact: false })).toBeTruthy();
  expect(screen.queryByPlaceholderText("파일 내용 검색")).toBeNull();

  fireEvent.keyDown(window, { key: "f", ctrlKey: true });

  const searchInput = await screen.findByPlaceholderText("파일 내용 검색");
  fireEvent.change(searchInput, { target: { value: "admin" } });
  expect(await screen.findByText("1/2")).toBeTruthy();

  fireEvent.keyDown(searchInput, { key: "Escape" });
  expect(screen.queryByPlaceholderText("파일 내용 검색")).toBeNull();
});

it("summarizes a service-version identification instead of leaving the operator to parse raw nmap stdout", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/executions/70/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "PORT   STATE SERVICE VERSION\n21/tcp open  ftp     vsftpd 3.0.3\n",
      stderr: "", status: "completed", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      { id: 8, project_id: 9, ip: "10.129.6.219" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets/8/services")) return Promise.resolve(new Response(JSON.stringify([
      { id: 22, port: 21, name: "ftp", product: "vsftpd", version: "3.0.3", extra_info: "" },
    ]), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 8, serviceId: 22 }} node={{
      id: "execution-70", type: "technique", status: "succeeded", objective: false, hidden: false,
      label: "제품·버전 식별",
      meta: JSON.stringify({ tool: "service-version" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 70 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("vsftpd 3.0.3")).toBeTruthy();
  expect(screen.getByText(/서비스에 자동 반영됨/)).toBeTruthy();
});

it("also summarizes telnet/database identification, not just service-version -- same auto-save promise", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/executions/71/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "PORT   STATE SERVICE VERSION\n23/tcp open  telnet  Linksys telnetd\n",
      stderr: "", status: "completed", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      { id: 8, project_id: 9, ip: "10.129.6.219" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets/8/services")) return Promise.resolve(new Response(JSON.stringify([
      { id: 23, port: 23, name: "telnet", product: "Linksys telnetd", version: "", extra_info: "" },
    ]), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 8, serviceId: 23 }} node={{
      id: "execution-71", type: "technique", status: "succeeded", objective: false, hidden: false,
      label: "Telnet 상세 정보 확인",
      meta: JSON.stringify({ tool: "telnet-info" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 71 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("Linksys telnetd")).toBeTruthy();
  expect(screen.getByText(/서비스에 자동 반영됨/)).toBeTruthy();
});

it("summarizes a target-level hostname/OS identification the same way, reading the persisted Target row", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/executions/72/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "Nmap scan report for 10.129.6.219\nOS details: Linux 5.0 - 5.4\n",
      stderr: "", status: "completed", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets")) return Promise.resolve(new Response(JSON.stringify([
      { id: 8, project_id: 9, ip: "10.129.6.219", hostname: "vain.htb", os_guess: "Linux 5.0 - 5.4" },
    ]), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 8 }} node={{
      id: "execution-72", type: "technique", status: "succeeded", objective: false, hidden: false,
      label: "운영체제·호스트명 식별",
      meta: JSON.stringify({ tool: "target-os-identity" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 72 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("vain.htb · Linux 5.0 - 5.4")).toBeTruthy();
  expect(screen.getByText(/Target에 자동 반영됨/)).toBeTruthy();
});

it("lets an unencrypted archive entry be dragged onto the canvas, same drag payload the file tree uses", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/findings/11")) return Promise.resolve(new Response(JSON.stringify({
      evidence: [{ id: 15, evidence_id: 124, title: "파일 다운로드: backup.zip",
        kind: "attachment", is_primary: true }],
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/evidence/124/archive")) return Promise.resolve(new Response(JSON.stringify({
      entries: [{ name: "index.php", size: 2560, encrypted: false }],
    }), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "finding-11", type: "finding", status: "untried", objective: false, hidden: false,
      label: "파일 다운로드: backup.zip",
      source_ref: JSON.stringify({ module: "findings", kind: "finding", id: 11 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  fireEvent.click(await screen.findByText("압축 해제"));
  const row = (await screen.findByText("index.php")).closest("div")!;

  const setData = vi.fn();
  fireEvent.dragStart(row, { dataTransfer: {setData, effectAllowed: ""} });

  expect(setData).toHaveBeenCalledWith(FILE_DRAG_MIME, JSON.stringify(
    { kind: "archive", evidenceId: 124, entry: "index.php" }));
});

it("lets a downloaded ftp file be dragged onto the canvas the same way", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/interactive-sessions?target_id=10")) return Promise.resolve(
      new Response(JSON.stringify([{ id: 37, command: "ftp 10.10.10.60 21", status: "stopped" }]),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/37/ftp-downloads")) return Promise.resolve(
      new Response(JSON.stringify({ files: [{ filename: "backup.zip", size: 2593 }] }),
        { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10 }} node={{
      id: "session-37", type: "technique", status: "succeeded", objective: false, hidden: false,
      label: "FTP 수동 접속",
      source_ref: JSON.stringify({ module: "sessions", kind: "session", id: 37 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  const card = (await screen.findByText("backup.zip")).closest("article")!;

  const setData = vi.fn();
  fireEvent.dragStart(card, { dataTransfer: {setData, effectAllowed: ""} });

  expect(setData).toHaveBeenCalledWith(FILE_DRAG_MIME, JSON.stringify(
    { kind: "ftp-download", sessionId: 37, filename: "backup.zip", graphNodeId: "session-37" }));
});

it("offers a one-click anonymous FTP session on an auto-detected ftp-anon finding", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/findings/14")) return Promise.resolve(new Response(JSON.stringify({
      target_id: 8, service_id: 3, evidence: [],
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions") && init?.method === "POST") {
      expect(JSON.parse(init.body as string)).toEqual({
        target_id: 8, service_id: 3,
        template_id: "ftp-client", variables: {port: "21"}, run_as_root: false,
        graph_node_id: "finding-14",
      });
      return Promise.resolve(new Response(JSON.stringify({ id: 55 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "finding-14", type: "finding", status: "untried", objective: false, hidden: false,
      label: "Ftp Anon on 10.129.7.93:21",
      source_ref: JSON.stringify({ module: "findings", kind: "finding", id: 14 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  const connectButton = await screen.findByText("익명으로 접속하기");
  await waitFor(() => expect((connectButton as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(connectButton);

  await waitFor(() => expect(screen.getByText("PTY #55")).toBeTruthy());
});

it("renders an ftp-directory-tree run as a real file tree, and promotes a clicked file", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/executions/90/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "F|backup.zip\nD|logs\nF|logs/access.log\n", stderr: "", status: "completed", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/executions/90/promote-ftp-file") && init?.method === "POST") {
      expect(JSON.parse(init.body as string)).toEqual({
        path: "backup.zip", graph_node_id: "execution-90",
      });
      return Promise.resolve(new Response(JSON.stringify({ finding_id: 1, evidence_id: 2 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "execution-90", type: "technique", status: "succeeded", objective: false, hidden: false,
      label: "폴더·파일 트리 조회",
      meta: JSON.stringify({ tool: "ftp-directory-tree" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 90 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  // Folders and files render through the shared tree widget (with its own
  // folder/file icons), not as raw "F|backup.zip" text.
  expect(await screen.findByText("backup.zip")).toBeTruthy();
  expect(screen.getByText("logs")).toBeTruthy();
  expect(screen.queryByText(/F\|backup\.zip/)).toBeNull();

  fireEvent.click(screen.getByText("backup.zip"));

  await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
    "/api/executions/90/promote-ftp-file", expect.objectContaining({ method: "POST" }),
  ));
  expect(await screen.findByText(/그래프에 남겼습니다/)).toBeTruthy();
});

it("lets a file in an ftp-directory-tree run be dragged onto the canvas too", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/executions/90/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "F|backup.zip", stderr: "", status: "completed", exit_code: 0,
    }), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "execution-90", type: "technique", status: "succeeded", objective: false, hidden: false,
      label: "폴더·파일 트리 조회",
      meta: JSON.stringify({ tool: "ftp-directory-tree" }),
      source_ref: JSON.stringify({ module: "executions", kind: "execution", id: 90 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  const file = await screen.findByText("backup.zip");
  const setData = vi.fn();
  fireEvent.dragStart(file, { dataTransfer: { setData, effectAllowed: "" } });

  expect(setData).toHaveBeenCalledWith(FILE_DRAG_MIME, JSON.stringify(
    { kind: "ftp-tree", executionId: 90, path: "backup.zip", graphNodeId: "execution-90" }));
});

it("auto-populates a folder/file tree on an ftp-client session's own node", async () => {
  // Every ftp-client session gets an anonymous ftp-directory-tree crawl
  // auto-started at session creation (sessions/router.py) -- the session's
  // own Inspector reads that run back by target+service instead of leaving
  // the operator to fetch a separate "폴더·파일 트리 조회" by hand for
  // something they're already sitting inside.
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/interactive-sessions?target_id=10")) return Promise.resolve(
      new Response(JSON.stringify([{ id: 37, command: "ftp 10.10.10.60 21", status: "running" }]),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/37/ftp-downloads")) return Promise.resolve(
      new Response(JSON.stringify({ files: [] }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/executions?target_id=10")) return Promise.resolve(new Response(JSON.stringify([
      { id: 91, template_id: "ftp-directory-tree", service_id: 5, status: "completed",
        stdout: "F|backup.zip" },
    ]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/executions/91/promote-ftp-file") && init?.method === "POST") {
      expect(JSON.parse(init.body as string)).toEqual({
        path: "backup.zip", graph_node_id: "session-37",
      });
      return Promise.resolve(new Response(JSON.stringify({ finding_id: 1, evidence_id: 2 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10, serviceId: 5 }} node={{
      id: "session-37", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "FTP 수동 접속", meta: JSON.stringify({ tool: "ftp-client" }),
      source_ref: JSON.stringify({ module: "sessions", kind: "session", id: 37 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  const file = await screen.findByText("backup.zip");
  fireEvent.click(file);

  await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
    "/api/executions/91/promote-ftp-file", expect.objectContaining({ method: "POST" }),
  ));
});

it("lets LinPEAS run and be analyzed directly from a manual-shell session node", async () => {
  // openManualShell/openSshShell in App.tsx (and ReverseShellPanel's nc/socat
  // listener buttons) all create their session through the generic manual
  // endpoint, which always stamps
  // template_id="manual-shell" -- reverse shells, SSH, psexec fallback shells
  // all look like this on the graph. The privesc-server + LinPEAS/pspy
  // trigger and the paste-and-analyze panel used to only be reachable from
  // PrivescSessionPanel/PostExploitationWorkspace; this is the same feature
  // surfaced inline on the session's own graph node instead.
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/interactive-sessions?target_id=10")) return Promise.resolve(
      new Response(JSON.stringify([{ id: 55, command: "nc -lvnp 4444", status: "running" }]),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/55/ftp-downloads")) return Promise.resolve(
      new Response(JSON.stringify({ files: [] }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/privesc-server/status")) return Promise.resolve(
      new Response(JSON.stringify({ running: false }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/privesc-server/start") && init?.method === "POST") return Promise.resolve(
      new Response(JSON.stringify({
        running: true, base_url: "http://10.10.14.5:8123", available: { peass: true, pspy: true },
      }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets/10/linpeas") && init?.method === "POST") return Promise.resolve(
      new Response(JSON.stringify({
        critical: ["CVE-2025-38236"], high: [], medium: [], evidence_id: 3,
      }), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10 }} node={{
      id: "session-55", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "nc -lvnp 4444", meta: JSON.stringify({ tool: "manual-shell" }),
      source_ref: JSON.stringify({ module: "sessions", kind: "session", id: 55 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(screen.queryByText("PTY #55")).toBeNull();
  fireEvent.click(await screen.findByText("세션 열기"));
  expect(await screen.findByText("PTY #55")).toBeTruthy();

  const linpeasButton = screen.getByText("LinPEAS 명령 셸에 입력");
  expect((linpeasButton as HTMLButtonElement).disabled).toBe(true);

  fireEvent.click(screen.getByText("서버 시작"));
  await waitFor(() => expect((linpeasButton as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(linpeasButton);
  expect(await screen.findByText(/linpeas\.sh \| bash/)).toBeTruthy();

  fireEvent.change(
    screen.getByPlaceholderText("linpeas.sh 실행 결과 전체를 붙여넣으세요"),
    { target: { value: "raw linpeas output" } },
  );
  fireEvent.click(screen.getByText("분석"));
  expect(await screen.findByText(/CVE-2025-38236/)).toBeTruthy();
});

it("also offers WinPEAS, SUID/GTFOBins analysis, and the Linux PrivEsc checklist on the same manual-shell node", async () => {
  // Same "put the whole PrivescSessionPanel/PostExploitationWorkspace toolset
  // on the session node" idea as the LinPEAS test above, but for the other
  // members of the same two categories: WinPEAS is LinPEAS's sibling in the
  // privesc-server trigger row (a manual-shell node can just as easily be a
  // Windows shell -- evil-winrm goes through this same generic endpoint),
  // SUID/GTFOBins is LinPEAS analysis's sibling paste-and-classify panel, and
  // the Linux PrivEsc reference is the third piece PrivescSessionPanel bundles
  // together (copy-only unless the session is open, same precondition as the
  // script triggers).
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/interactive-sessions?target_id=10")) return Promise.resolve(
      new Response(JSON.stringify([{ id: 55, command: "nc -lvnp 4444", status: "running" }]),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/55/ftp-downloads")) return Promise.resolve(
      new Response(JSON.stringify({ files: [] }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/privesc-server/status")) return Promise.resolve(
      new Response(JSON.stringify({ running: false }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/privesc-server/start") && init?.method === "POST") return Promise.resolve(
      new Response(JSON.stringify({
        running: true, base_url: "http://10.10.14.5:8123", available: { peass: true, pspy: true },
      }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/targets/10/suid-scan") && init?.method === "POST") return Promise.resolve(
      new Response(JSON.stringify({
        matches: [{ path: "/usr/bin/find", binary: "find",
          command: "find . -exec /bin/sh -p \\; -quit",
          reference: "https://gtfobins.github.io/gtfobins/find/#suid" }], evidence_id: 7,
      }), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10 }} node={{
      id: "session-55", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "nc -lvnp 4444", meta: JSON.stringify({ tool: "manual-shell" }),
      source_ref: JSON.stringify({ module: "sessions", kind: "session", id: 55 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  fireEvent.click(await screen.findByText("세션 열기"));
  expect(await screen.findByText("PTY #55")).toBeTruthy();

  const winpeasButton = screen.getByText("WinPEAS 명령 셸에 입력");
  expect((winpeasButton as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByText("서버 시작"));
  await waitFor(() => expect((winpeasButton as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(winpeasButton);
  expect(await screen.findByText(/winPEASany\.exe/)).toBeTruthy();

  fireEvent.change(
    screen.getByPlaceholderText("find / -perm -4000 -type f 2>/dev/null 결과를 붙여넣으세요"),
    { target: { value: "/usr/bin/find" } },
  );
  fireEvent.click(screen.getByText("SUID 분석"));
  expect(await screen.findByText("/usr/bin/find")).toBeTruthy();

  fireEvent.click(screen.getByText("Linux PrivEsc 참고 열기"));
  fireEvent.click(screen.getAllByText("셸에 입력")[0]);
  expect(await screen.findByText(/전송: .id/)).toBeTruthy();
});

it("also offers the Windows PrivEsc checklist on the same manual-shell node -- evil-winrm sessions are manual-shell too", async () => {
  // manual-shell isn't Linux-specific: openEvilWinrmShell in App.tsx goes
  // through the exact same generic /interactive-sessions/manual endpoint.
  // The Linux checklist (pg_hba.conf etc.) was already wired in; the
  // Windows equivalent (PowerShell history -- the single most common
  // "service account password turns out to be the domain admin's too"
  // discovery, e.g. HTB Archetype) had no graph-reachable home at all
  // before this, only the SSH/wmiexec-only catalog runner in
  // PostExploitationWorkspace.
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/interactive-sessions?target_id=10")) return Promise.resolve(
      new Response(JSON.stringify([{ id: 70, command: "evil-winrm -i 10.129.4.83 -u Administrator",
        status: "running" }]), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/70/ftp-downloads")) return Promise.resolve(
      new Response(JSON.stringify({ files: [] }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/privesc-server/status")) return Promise.resolve(
      new Response(JSON.stringify({ running: false }),
        { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10 }} node={{
      id: "session-70", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "evil-winrm -i 10.129.4.83 -u Administrator", meta: JSON.stringify({ tool: "manual-shell" }),
      source_ref: JSON.stringify({ module: "sessions", kind: "session", id: 70 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  fireEvent.click(await screen.findByText("세션 열기"));
  await screen.findByText("PTY #70");

  fireEvent.click(screen.getByText("Windows PrivEsc 참고 열기"));
  expect(screen.getByText("PowerShell 히스토리·저장된 자격증명")).toBeTruthy();
  fireEvent.click(screen.getByText("type (Get-PSReadlineOption).HistorySavePath")
    .closest(".sqlPayloadRow")!.querySelector("button:last-child")!);
  expect(await screen.findByText(/전송: .type \(Get-PSReadlineOption\)/)).toBeTruthy();
});

it("reads a real folder/file tree off the already-open manual-shell PTY, no SSH credential needed", async () => {
  // The "다른 자격증명으로 조회 (SSH)" button next to this one requires a
  // stored credential and a fresh SSH/wmiexec connection -- useless for a
  // bare `nc` reverse shell like this one, which has none. This is the
  // fix: type a marker-wrapped find one-liner into the PTY the operator
  // already has open, then read it back off the session's own persisted
  // log and parse the D|/F| segment between the two markers.
  vi.spyOn(Date, "now").mockReturnValue(999);
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/interactive-sessions?target_id=10")) return Promise.resolve(
      new Response(JSON.stringify([{ id: 55, command: "nc -lvnp 4444", status: "running" }]),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/55/ftp-downloads")) return Promise.resolve(
      new Response(JSON.stringify({ files: [] }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/privesc-server/status")) return Promise.resolve(
      new Response(JSON.stringify({ running: false }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/55/log")) return Promise.resolve(new Response(
      "postgres@vaccine:~$ echo ___TREE_START_999___; find ...; echo ___TREE_END_999___\n" +
      "___TREE_START_999___\n" +
      "D|/var/www\nD|/var/www/html\nF|/var/www/html/dashboard.php\n" +
      "___TREE_END_999___\n" +
      "postgres@vaccine:~$ "));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10 }} node={{
      id: "session-55", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "nc -lvnp 4444", meta: JSON.stringify({ tool: "manual-shell" }),
      source_ref: JSON.stringify({ module: "sessions", kind: "session", id: 55 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  fireEvent.click(await screen.findByText("세션 열기"));
  await screen.findByText("PTY #55");

  const treeButton = screen.getByText("폴더·파일 트리 조회 (현재 셸)");
  fireEvent.click(treeButton);
  expect(await screen.findByText(/___TREE_START_999___/)).toBeTruthy();

  expect(await screen.findByText("www")).toBeTruthy();
  // Nested folders render collapsed (<details> without `open`) until a
  // search query forces every level open -- same UX as the ftp-client tree.
  fireEvent.change(screen.getByPlaceholderText("이름으로 검색…"),
    { target: { value: "dashboard" } });
  expect(await screen.findByText("dashboard.php")).toBeTruthy();

  vi.restoreAllMocks();
});

it("offers a 다시 시작 button on a dead manual-shell session, same as responder already has", async () => {
  // A dead nc listener (or any manual-shell session whose underlying
  // process exited -- interrupted/failed/stopped all map to graph status
  // "attempt-failed") had no way back except leaving the node and opening
  // a whole new listener from scratch. retry() and its POST endpoint were
  // already generic (Responder already used them), just never wired up
  // for this node type -- "세션 열기" only re-attaches to a still-live
  // process, it can't resurrect a dead one.
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/interactive-sessions?target_id=10")) return Promise.resolve(
      new Response(JSON.stringify([{ id: 65, command: "nc -lvnp 4444", status: "interrupted" }]),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/65/ftp-downloads")) return Promise.resolve(
      new Response(JSON.stringify({ files: [] }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/privesc-server/status")) return Promise.resolve(
      new Response(JSON.stringify({ running: false }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/65/retry") && init?.method === "POST")
      return Promise.resolve(new Response(JSON.stringify({ id: 66, command: "nc -lvnp 4444" }),
        { status: 201, headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10 }} node={{
      id: "session-65", type: "technique", status: "attempt-failed", objective: false, hidden: false,
      label: "nc -lvnp 4444", meta: JSON.stringify({ tool: "manual-shell" }),
      source_ref: JSON.stringify({ module: "sessions", kind: "session", id: 65 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(screen.queryByText("세션 열기")).toBeNull();
  fireEvent.click(await screen.findByText("다시 시작 (nc -lvnp 4444)"));

  expect(await screen.findByText("PTY #66")).toBeTruthy();
});

it("clears the pending line before each trigger instead of piling commands up, and auto-runs only the read-only file-tree query", async () => {
  // A user report: clicking LinPEAS twice (or LinPEAS then WinPEAS) kept
  // appending onto whatever was already sitting unexecuted at the prompt,
  // turning into one unusable run-on line -- nothing ever actually ran,
  // and it looked like the buttons did nothing at all. Every trigger now
  // leads with Ctrl-U (\x15) to clear the line first. Separately, the
  // file-tree query is the one trigger that's a hardcoded, read-only `find`
  // -- unlike LinPEAS/WinPEAS (fetch and run a third-party script), it gets
  // to skip the "operator reviews and presses Enter" step and just runs.
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/interactive-sessions?target_id=10")) return Promise.resolve(
      new Response(JSON.stringify([{ id: 55, command: "nc -lvnp 4444", status: "running" }]),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/55/ftp-downloads")) return Promise.resolve(
      new Response(JSON.stringify({ files: [] }),
        { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/privesc-server/status")) return Promise.resolve(
      new Response(JSON.stringify({
        running: true, base_url: "http://10.10.14.5:8123", available: { peass: true, pspy: true },
      }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/interactive-sessions/55/log")) return Promise.resolve(new Response(""));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector executionContext={{ targetId: 10 }} node={{
      id: "session-55", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "nc -lvnp 4444", meta: JSON.stringify({ tool: "manual-shell" }),
      source_ref: JSON.stringify({ module: "sessions", kind: "session", id: 55 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  fireEvent.click(await screen.findByText("세션 열기"));
  await screen.findByText("PTY #55");
  await waitFor(() => expect(
    (screen.getByText("LinPEAS 명령 셸에 입력") as HTMLButtonElement).disabled).toBe(false));

  fireEvent.click(screen.getByText("LinPEAS 명령 셸에 입력"));
  const afterLinpeas = screen.getByTestId("raw-input-request").getAttribute("data-command")!;
  expect(afterLinpeas.startsWith("\x15")).toBe(true);
  expect(afterLinpeas.endsWith("\r")).toBe(false);

  fireEvent.click(screen.getByText("WinPEAS 명령 셸에 입력"));
  const afterWinpeas = screen.getByTestId("raw-input-request").getAttribute("data-command")!;
  expect(afterWinpeas.startsWith("\x15")).toBe(true);
  expect(afterWinpeas).not.toContain(afterLinpeas.slice(1));

  fireEvent.click(screen.getByText("폴더·파일 트리 조회 (현재 셸)"));
  const afterTree = screen.getByTestId("raw-input-request").getAttribute("data-command")!;
  expect(afterTree.startsWith("\x15")).toBe(true);
  expect(afterTree.endsWith("\r")).toBe(true);
});

it("shows a hash-crack job's live output and lets a cracked hash be promoted", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/hash-cracking/42")) return Promise.resolve(new Response(JSON.stringify({
      status: "running", exit_code: null, cracked_count: 1, hash_count: 1,
      command_display: "hashcat -m 17200 ...",
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/hash-cracking/42/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "hashcat (v7.1.2) starting...", stderr: "",
      cracked: [{ hash: "$pkzip$1*...*$/pkzip$", plain: "hunter2" }],
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/hash-cracking/42/promote") && init?.method === "POST") {
      expect(JSON.parse(init.body as string)).toEqual({ username: "admin", secret: "hunter2" });
      return Promise.resolve(new Response(JSON.stringify({ id: 5 }), {
        status: 201, headers: { "Content-Type": "application/json" },
      }));
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "crack-42", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "해시 크래킹 · PKZIP/ZipCrypto",
      source_ref: JSON.stringify({ module: "hash_cracking", kind: "hash_crack_job", id: 42 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText(/hashcat \(v7\.1\.2\) starting/)).toBeTruthy();
  expect(await screen.findByText("hunter2")).toBeTruthy();

  fireEvent.change(screen.getByPlaceholderText("사용자명"), { target: { value: "admin" } });
  fireEvent.click(screen.getByText("그래프에 남기기"));

  await waitFor(() => expect(fetcher).toHaveBeenCalledWith(
    "/api/hash-cracking/42/promote", expect.objectContaining({ method: "POST" }),
  ));
  expect(await screen.findByText(/admin 그래프에 남겼습니다/)).toBeTruthy();
});

it("copies a cracked plaintext to the clipboard without needing to drag-select it", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/hash-cracking/42")) return Promise.resolve(new Response(JSON.stringify({
      status: "running", exit_code: null, cracked_count: 1, hash_count: 1,
      command_display: "hashcat -m 17200 ...",
    }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/hash-cracking/42/output")) return Promise.resolve(new Response(JSON.stringify({
      stdout: "hashcat (v7.1.2) starting...", stderr: "",
      cracked: [{ hash: "$pkzip$1*...*$/pkzip$", plain: "hunter2" }],
    }), { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const writeText = vi.fn(() => Promise.resolve());
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

  render(<QueryClientProvider client={client}>
    <Inspector node={{
      id: "crack-42", type: "technique", status: "in-progress", objective: false, hidden: false,
      label: "해시 크래킹 · PKZIP/ZipCrypto",
      source_ref: JSON.stringify({ module: "hash_cracking", kind: "hash_crack_job", id: 42 }),
    }} busy={false} onToggleHidden={vi.fn()} onSetStatus={vi.fn()} onAddNode={vi.fn()} />
  </QueryClientProvider>);

  expect(await screen.findByText("hunter2")).toBeTruthy();
  fireEvent.click(screen.getByText("복사"));

  await waitFor(() => expect(writeText).toHaveBeenCalledWith("hunter2"));
});
