// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import WebWorkspace from "./WebWorkspace";

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
  expect(screen.getByText(/SQLi 페이로드 \d+개가 대기 중입니다\./)).toBeTruthy();
});
