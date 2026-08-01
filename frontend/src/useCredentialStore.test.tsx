// @vitest-environment jsdom
import React from "react";
import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { useCredentialStore } from "./useCredentialStore";

const response = (body: unknown) => Promise.resolve(new Response(
  JSON.stringify(body), { headers: { "Content-Type": "application/json" } },
));

afterEach(() => {
  vi.unstubAllGlobals();
});

function wrapper(client: QueryClient) {
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}

it("applies a saved credential's stored secret into the live password field", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL) => {
    if (String(input).includes("/api/runbooks/credentials?project_id=1"))
      return response([{
        id: 1, username: "svc_sql", domain: "CORP", secret: "Summer2026!",
        has_secret: true, secret_hint: "", source_kind: "kerberoast",
        source_detail: "kerberoast-hashes.txt",
      }]);
    throw new Error(`Unhandled request: ${input}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { result } = renderHook(
    () => useCredentialStore({ projectId: 1, targetId: 2, serviceId: 3 }),
    { wrapper: wrapper(client) },
  );
  await waitFor(() => expect(result.current.saved.data).toHaveLength(1));

  act(() => result.current.apply(result.current.saved.data![0]));

  expect(result.current.username).toBe("svc_sql");
  expect(result.current.domain).toBe("CORP");
  // The whole point of storing a secret is skipping re-entry on reuse.
  expect(result.current.password).toBe("Summer2026!");
  expect(result.current.sourceKind).toBe("kerberoast");
});

it("only sends the live password to the server when storeSecret is opted in", async () => {
  const bodies: unknown[] = [];
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("/api/runbooks/credentials?project_id=1")) return response([]);
    if (url.endsWith("/api/runbooks/credentials") && init?.method === "POST") {
      bodies.push(JSON.parse(String(init.body)));
      return response({ id: 9 });
    }
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { result } = renderHook(
    () => useCredentialStore({ projectId: 1, targetId: 2, serviceId: 3, serviceName: "smb" }),
    { wrapper: wrapper(client) },
  );
  await waitFor(() => expect(result.current.saved.isFetched).toBe(true));

  act(() => {
    result.current.setUsername("guest");
    result.current.setPassword("hunter2");
  });
  await act(async () => { await result.current.save(); });

  expect(bodies).toEqual([expect.objectContaining({ username: "guest", secret: "" })]);

  act(() => result.current.setStoreSecret(true));
  await act(async () => { await result.current.save(); });

  expect(bodies[1]).toMatchObject({ username: "guest", secret: "hunter2" });
});

it("invalidates the saved-credential list after deleting one", async () => {
  let listCalls = 0;
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes("/api/runbooks/credentials?project_id=1")) {
      listCalls += 1;
      return response([]);
    }
    if (url.endsWith("/api/runbooks/credentials/5") && init?.method === "DELETE")
      return Promise.resolve(new Response(null, { status: 204 }));
    throw new Error(`Unhandled request: ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const { result } = renderHook(
    () => useCredentialStore({ projectId: 1 }),
    { wrapper: wrapper(client) },
  );
  await waitFor(() => expect(listCalls).toBe(1));

  await act(async () => { await result.current.remove(5); });

  await waitFor(() => expect(listCalls).toBe(2));
});
