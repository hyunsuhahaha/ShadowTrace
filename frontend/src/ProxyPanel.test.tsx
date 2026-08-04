// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import ProxyPanel from "./ProxyPanel";

const idleStatus = { running: false, stderr_tail: [] };
const runningStatus = { running: true, port: 8081, target_ip: "10.129.219.134", stderr_tail: [] };
const capturedRequest = {
  id: 9, project_id: 1, target_id: 2, name: "POST http://10.129.219.134/login.php",
  folder: "Proxy Capture", tags: '["proxy-capture"]', method: "POST",
  url: "http://10.129.219.134/login.php", query: "{}", headers: "{}", cookies: "{}",
  body: "username=admin&password=x", body_mode: "raw", tls_verify: true,
  proxy: "", timeout: 30, follow_redirects: false,
};

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(
    status === 204 ? null : JSON.stringify(body),
    { status, headers: { "Content-Type": "application/json" } },
  ));
}

function mount(fetcher: ReturnType<typeof vi.fn>, props: Partial<Parameters<typeof ProxyPanel>[0]> = {}) {
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  return render(
    <QueryClientProvider client={client}>
      <ProxyPanel projectId={1} targetId={2} onOpenRequest={vi.fn()} onSendToIntruder={vi.fn()} {...props} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("warns when no target is selected and disables start", async () => {
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/web/proxy/status") return response(idleStatus);
    if (url.startsWith("/api/web/proxy/captures")) return response([]);
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher, { projectId: undefined, targetId: undefined });

  await screen.findByText("대상을 먼저 선택하세요.");
  expect((screen.getByText("시작") as HTMLButtonElement).disabled).toBe(true);
});

it("starts the proxy with the chosen port and project/target scope", async () => {
  const fetcher = vi.fn((url: string, init?: RequestInit) => {
    if (url === "/api/web/proxy/status") return response(idleStatus);
    if (url.startsWith("/api/web/proxy/captures")) return response([]);
    if (url === "/api/web/proxy/start" && init?.method === "POST") return response({ ok: true });
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("중지됨");
  fireEvent.click(screen.getByText("시작"));

  await waitFor(() => expect(fetcher).toHaveBeenCalledWith("/api/web/proxy/start", expect.objectContaining({
    method: "POST",
  })));
  const [, init] = fetcher.mock.calls.find(([url]) => url === "/api/web/proxy/start")!;
  expect(JSON.parse((init as RequestInit).body as string)).toEqual({
    project_id: 1, target_id: 2, port: 8081,
  });
});

it("shows the CA cert link and browser setup instructions while running", async () => {
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/web/proxy/status") return response(runningStatus);
    if (url.startsWith("/api/web/proxy/captures")) return response([]);
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("실행 중 · 127.0.0.1:8081");
  expect(screen.getByText("CA 인증서 다운로드").closest("a")?.getAttribute("href"))
    .toBe("/api/web/proxy/ca-cert");
  expect(screen.getByText("중지")).toBeTruthy();
});

it("stops the proxy on click", async () => {
  const fetcher = vi.fn((url: string, init?: RequestInit) => {
    if (url === "/api/web/proxy/status") return response(runningStatus);
    if (url.startsWith("/api/web/proxy/captures")) return response([]);
    if (url === "/api/web/proxy/stop" && init?.method === "POST") return response({ ok: true });
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("중지");
  fireEvent.click(screen.getByText("중지"));

  await waitFor(() => expect(fetcher).toHaveBeenCalledWith("/api/web/proxy/stop", expect.objectContaining({
    method: "POST",
  })));
});

it("lists captured requests and wires the open/Intruder actions", async () => {
  const onOpenRequest = vi.fn();
  const onSendToIntruder = vi.fn();
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/web/proxy/status") return response(runningStatus);
    if (url.startsWith("/api/web/proxy/captures")) return response([capturedRequest]);
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher, { onOpenRequest, onSendToIntruder });

  await screen.findByText("캡처된 요청 · 1개");
  expect(screen.getByText("POST http://10.129.219.134/login.php")).toBeTruthy();

  fireEvent.click(screen.getByText("Request로 열기"));
  expect(onOpenRequest).toHaveBeenCalledWith(capturedRequest);

  fireEvent.click(screen.getByText("Intruder로"));
  expect(onSendToIntruder).toHaveBeenCalledWith(capturedRequest);
});

it("surfaces the last mitmdump stderr lines when present", async () => {
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/web/proxy/status")
      return response({ ...idleStatus, stderr_tail: ["Address already in use"] });
    if (url.startsWith("/api/web/proxy/captures")) return response([]);
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("Address already in use");
});
