// @vitest-environment jsdom
import React from "react";
import {renderHook, waitFor} from "@testing-library/react";
import {QueryClient, QueryClientProvider} from "@tanstack/react-query";
import {afterEach, expect, it, vi} from "vitest";
import {useEnumerationQueries} from "./useEnumerationQueries";

const response = (_input?: RequestInfo | URL) => Promise.resolve(new Response(JSON.stringify([]), {
  headers: {"Content-Type": "application/json"},
}));

afterEach(() => vi.unstubAllGlobals());

it("enables each query only when its scope id is available", async () => {
  const fetcher = vi.fn(response);
  vi.stubGlobal("fetch", fetcher);
  const client = new QueryClient({
    defaultOptions: {queries: {retry: false}},
  });
  const wrapper = ({children}: {children: React.ReactNode}) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  const {rerender} = renderHook(
    (ids: {projectId?: number; targetId?: number; serviceId?: number}) =>
      useEnumerationQueries(ids),
    {initialProps: {}, wrapper},
  );

  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
  expect(fetcher).toHaveBeenCalledWith("/api/projects", undefined);

  rerender({projectId: 1, targetId: 2, serviceId: 3});
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(7));
  expect(fetcher.mock.calls.map(([url]) => url)).toEqual(expect.arrayContaining([
    "/api/projects",
    "/api/targets?project_id=1",
    "/api/targets/2/services",
    "/api/services/3/commands",
    "/api/services/3/intelligence",
    "/api/targets/2/identity-commands",
    "/api/executions?target_id=2",
  ]));
});
