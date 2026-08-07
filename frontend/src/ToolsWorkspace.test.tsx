// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import ToolsWorkspace from "./ToolsWorkspace";

const project = { id: 1, name: "Lab" };
const target = { id: 2, project_id: 1, name: "box", ip: "10.10.10.60", hostname: "" };
const service = { id: 5, target_id: 2, port: 80, protocol: "tcp", name: "http" };
const catalog = {
  groups: [{
    key: "http", display_name: "HTTP", commands: [{
      id: "http-directory-fuzz", name: "디렉터리·파일 퍼징 (feroxbuster)",
      description: "정적 워드리스트로 존재하는 경로를 찾습니다.", risk: "medium",
      tool: "feroxbuster", execution_mode: "captured",
      command: "feroxbuster -u {scheme}://{host}:{port}/ -w {wordlist} --json --silent -n",
      needs_service: true, variables: ["wordlist"],
    }],
  }],
};

class FakeEventSource {
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  close() {}
}

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(
    status === 204 ? null : JSON.stringify(body),
    { status, headers: { "Content-Type": "application/json" } },
  ));
}

function baseFetcher(extra: (url: string, init?: RequestInit) => Response | undefined) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const handled = extra(url, init);
    if (handled) return Promise.resolve(handled);
    if (url.endsWith("/api/projects")) return response([project]);
    if (url.endsWith("/api/targets")) return response([target]);
    if (url.endsWith("/api/targets/2/services")) return response([service]);
    if (url.endsWith("/api/tool-catalog")) return response(catalog);
    if (url.includes("/api/executions?target_id=2")) return response([]);
    throw new Error(`Unhandled request: ${url} ${init?.method}`);
  });
}

function mount(fetcher: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("fetch", fetcher);
  vi.stubGlobal("EventSource", FakeEventSource);
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  return render(
    <QueryClientProvider client={client}><ToolsWorkspace /></QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  localStorage.clear();
});

it("lists catalog commands grouped by category and previews the selected one", async () => {
  mount(baseFetcher(() => undefined));
  await screen.findByText("HTTP");
  fireEvent.click(screen.getByText("디렉터리·파일 퍼징 (feroxbuster)"));

  expect(await screen.findByText(/\{port\}.*-w \{wordlist\}/)).toBeTruthy();
  expect(screen.getByText("위험도 medium · feroxbuster")).toBeTruthy();
});

it("fills in host/port from a selected service and disables run until the wordlist is set", async () => {
  mount(baseFetcher(() => undefined));
  await screen.findByText("HTTP");
  fireEvent.click(screen.getByText("디렉터리·파일 퍼징 (feroxbuster)"));
  const runButton = await screen.findByText("실행 내용 검토") as HTMLButtonElement;
  expect(runButton.disabled).toBe(true);

  await screen.findByText("80/tcp · http");
  fireEvent.change(screen.getByLabelText("서비스 (있으면 선택 · 없으면 아래 직접 입력)"), {
    target: { value: "5" },
  });
  expect(await screen.findByText(
    "feroxbuster -u http://10.10.10.60:80/ -w {wordlist} --json --silent -n")).toBeTruthy();
  expect(runButton.disabled).toBe(true);

  fireEvent.change(screen.getByLabelText("워드리스트 경로"), {
    target: { value: "/usr/share/wordlists/dirb/common.txt" },
  });
  expect(runButton.disabled).toBe(false);
});

it("runs the selected command against the chosen service after review confirmation", async () => {
  const fetcher = baseFetcher((url, init) => {
    if (url.endsWith("/api/executions") && init?.method === "POST") {
      return new Response(JSON.stringify({
        id: 9, target_id: 2, service_id: 5, template_id: "http-directory-fuzz",
        command: "feroxbuster ...", stdout: "", stderr: "", status: "queued", error: "",
        started_at: new Date().toISOString(),
      }), { status: 201, headers: { "Content-Type": "application/json" } });
    }
    return undefined;
  });
  mount(fetcher);
  await screen.findByText("HTTP");
  fireEvent.click(screen.getByText("디렉터리·파일 퍼징 (feroxbuster)"));
  await screen.findByText("80/tcp · http");
  fireEvent.change(screen.getByLabelText("서비스 (있으면 선택 · 없으면 아래 직접 입력)"), {
    target: { value: "5" },
  });
  await screen.findByText("feroxbuster -u http://10.10.10.60:80/ -w {wordlist} --json --silent -n");
  fireEvent.change(screen.getByLabelText("워드리스트 경로"), {
    target: { value: "/usr/share/wordlists/dirb/common.txt" },
  });
  await waitFor(() => expect((screen.getByText("실행 내용 검토") as HTMLButtonElement).disabled)
    .toBe(false));
  fireEvent.click(screen.getByText("실행 내용 검토"));
  fireEvent.click(await screen.findByText("명령 실행"));

  await waitFor(() => {
    const call = fetcher.mock.calls.find(([callUrl, callInit]) =>
      String(callUrl).endsWith("/api/executions") && callInit?.method === "POST");
    expect(call).toBeTruthy();
    const body = JSON.parse(String(call?.[1]?.body));
    expect(body.target_id).toBe(2);
    expect(body.service_id).toBe(5);
    expect(body.template_id).toBe("http-directory-fuzz");
    expect(body.variables).toEqual({ wordlist: "/usr/share/wordlists/dirb/common.txt" });
  });
});

it("filters the catalog by search text", async () => {
  mount(baseFetcher(() => undefined));
  await screen.findByText("HTTP");
  fireEvent.change(screen.getByLabelText("명령 검색"), { target: { value: "존재하지않음xyz" } });

  expect(screen.queryByText("디렉터리·파일 퍼징 (feroxbuster)")).toBeNull();
  expect(screen.getByText("검색어와 일치하는 명령이 없습니다.")).toBeTruthy();
});
