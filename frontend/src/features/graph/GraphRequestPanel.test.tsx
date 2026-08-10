// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GraphRequestPanel } from "./GraphRequestPanel";

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});

it("inserts the tun0 responder path without leaving the graph request panel", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify({
    tun0: "tun0 UNKNOWN 10.10.16.178/23",
  }), { headers: { "Content-Type": "application/json" } }))));
  location.hash = "#graph";
  render(<GraphRequestPanel draft={{ projectId: 3, targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=french.html" }} onBack={vi.fn()} />);

  fireEvent.click(await screen.findByText("RESPONDER IP · 10.10.16.178"));
  expect((screen.getByLabelText("Request URL") as HTMLInputElement).value)
    .toBe("http://unika.htb/index.php?page=\\\\10.10.16.178\\test");
  expect(location.hash).toBe("#graph");
});
