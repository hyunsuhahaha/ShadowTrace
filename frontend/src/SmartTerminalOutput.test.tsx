// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen, waitFor} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import SmartTerminalOutput, {parseTerminalMatches} from "./SmartTerminalOutput";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); localStorage.clear(); });

it("parses open services, URLs and valid IPs without overlapping URL hosts", () => {
  const output = "80/tcp open http\nvisit http://10.10.10.60/admin\npeer 10.10.10.61\nbad 999.1.1.1";
  expect(parseTerminalMatches(output).map((item) => [item.kind, item.value])).toEqual([
    ["service", "80/tcp open http"],
    ["url", "http://10.10.10.60/admin"],
    ["ip", "10.10.10.61"],
  ]);
});

it("opens smart actions from a parsed terminal token", () => {
  render(<pre><SmartTerminalOutput output="80/tcp open http" context={{targetId: 2}} /></pre>);
  fireEvent.click(screen.getByText("80/tcp open http"));
  expect(screen.getByText("＋ ADD AS CHILD NODE")).toBeTruthy();
  expect(screen.getByText("🚀 STAGE FEROX / FFUF")).toBeTruthy();
});

it("adds an approved service candidate under the current host", async () => {
  const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const json = (body: unknown) => Promise.resolve(new Response(JSON.stringify(body), {
      status: 200, headers: {"Content-Type": "application/json"},
    }));
    if (url.endsWith("/graph/sync")) return json({});
    if (url.endsWith("/graph") && !init?.method) return json({root_node_id: "root", edges: [], nodes: [
      {id: "host", type: "host", label: "10.0.0.1", status: "untried", objective: false,
        hidden: false, source_ref: JSON.stringify({kind: "target", id: 2})},
    ]});
    if (url.endsWith("/graph/nodes")) return json({id: "service"});
    if (url.endsWith("/graph/edges")) return json({id: "edge"});
    throw new Error(`Unhandled ${url}`);
  });
  vi.stubGlobal("fetch", fetcher);
  render(<pre><SmartTerminalOutput output="80/tcp open http"
    context={{projectId: 1, targetId: 2, targetIp: "10.0.0.1"}} /></pre>);

  fireEvent.click(screen.getByText("80/tcp open http"));
  fireEvent.click(screen.getByText("＋ ADD AS CHILD NODE"));

  await waitFor(() => expect(screen.getByText("ADDED · 80/tcp http")).toBeTruthy());
  const edgeCall = fetcher.mock.calls.find(([url]) => String(url).endsWith("/graph/edges"));
  expect(JSON.parse(String(edgeCall?.[1]?.body))).toMatchObject({
    source: "host", target: "service", relation: "discovered",
  });
});
