// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GraphRequestPanel } from "./GraphRequestPanel";

afterEach(() => {
  cleanup();
  localStorage.clear();
  vi.unstubAllGlobals();
});

it("inserts an SMB direct injection path without leaving the graph request panel", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify({
    tun0: "tun0 UNKNOWN 10.10.16.178/23",
  }), { headers: { "Content-Type": "application/json" } }))));
  location.hash = "#graph";
  render(<GraphRequestPanel draft={{ projectId: 3, targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=french.html" }} onBack={vi.fn()} />);

  fireEvent.click(await screen.findByText("SMB Direct Injection 시도"));
  expect((screen.getByLabelText("Request URL") as HTMLInputElement).value)
    .toBe("http://unika.htb/index.php?page=\\\\10.10.16.178\\test");
  expect(location.hash).toBe("#graph");
});

it("inserts a nonexistent host path for an LLMNR attempt", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(JSON.stringify({
    tun0: "tun0 UNKNOWN 10.10.16.178/23",
  }), { headers: { "Content-Type": "application/json" } }))));
  render(<GraphRequestPanel draft={{ projectId: 3, targetId: 10, serviceId: 20,
    url: "http://unika.htb/index.php?page=french.html" }} onBack={vi.fn()} />);

  fireEvent.click(screen.getByText("LLMNR 시도"));
  expect((screen.getByLabelText("Request URL") as HTMLInputElement).value)
    .toBe("http://unika.htb/index.php?page=\\\\UNKNOWN-SERVER\\share");
});
