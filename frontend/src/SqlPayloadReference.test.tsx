// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import SqlPayloadReference from "./SqlPayloadReference";
import { findSqlPayloadCategory, sqlPayloadCategories } from "./sqlPayloads";

const authBypass = sqlPayloadCategories.find((category) => category.id === "auth-bypass")!;

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

it("renders every payload category as a copyable reference, not an executable form", async () => {
  vi.stubGlobal("fetch", stubVpnStatus());
  render(<SqlPayloadReference />);

  expect(screen.getByText("UNION 기반 추출")).toBeTruthy();
  expect(screen.getByText("MSSQL xp_cmdshell")).toBeTruthy();
  await screen.findByText(/^10\.10\.14\.5$/);
});

it("fills LHOST and LPORT into the postgres COPY FROM PROGRAM reverse shell payload", async () => {
  vi.stubGlobal("fetch", stubVpnStatus("10.10.14.5"));
  render(<SqlPayloadReference />);
  await screen.findByText(/^10\.10\.14\.5$/);

  const category = findSqlPayloadCategory("postgres-copy-program")!;
  const revshell = category.payloads.find((item) => item.payload.startsWith("';"))!;
  const resolved = revshell.payload.replace("{LHOST}", "10.10.14.5").replace("{LPORT}", "4444");
  expect(screen.getByText(resolved)).toBeTruthy();
});

it("fills LHOST and LPORT into the MSSQL xp_cmdshell and MySQL reverse shell payloads too", async () => {
  vi.stubGlobal("fetch", stubVpnStatus("10.10.14.5"));
  render(<SqlPayloadReference />);
  await screen.findByText(/^10\.10\.14\.5$/);

  const mssql = findSqlPayloadCategory("mssql-xp-cmdshell")!;
  const mssqlShell = mssql.payloads.find((item) => item.label.startsWith("리버스 쉘")
    && !item.payload.startsWith("';"))!;
  expect(screen.getByText(mssqlShell.payload
    .replaceAll("{LHOST}", "10.10.14.5").replaceAll("{LPORT}", "4444"))).toBeTruthy();

  const udf = findSqlPayloadCategory("mysql-udf-rce")!;
  const udfShell = udf.payloads.find((item) => item.payload.includes("{LHOST}"))!;
  expect(screen.getByText(udfShell.payload
    .replace("{LHOST}", "10.10.14.5").replace("{LPORT}", "4444"))).toBeTruthy();
});

it("copies a resolved payload to the clipboard without sending any network request beyond vpn/status", async () => {
  const writeText = vi.fn(() => Promise.resolve());
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
  const fetcher = stubVpnStatus();
  vi.stubGlobal("fetch", fetcher);
  render(<SqlPayloadReference />);
  await screen.findByText(/^10\.10\.14\.5$/);

  fireEvent.click(screen.getAllByText("복사")[0]);

  await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it("hides the Intruder handoff buttons when no handler is given", async () => {
  vi.stubGlobal("fetch", stubVpnStatus());
  render(<SqlPayloadReference />);
  await screen.findByText(/^10\.10\.14\.5$/);

  expect(screen.queryByText("Intruder로")).toBeNull();
  expect(screen.queryByText(/Intruder 후보로 보내기/)).toBeNull();
});

it("stages a single payload for Intruder without sending any network request beyond vpn/status", async () => {
  const fetcher = stubVpnStatus();
  vi.stubGlobal("fetch", fetcher);
  const onSendToIntruder = vi.fn();
  render(<SqlPayloadReference onSendToIntruder={onSendToIntruder} />);
  await screen.findByText(/^10\.10\.14\.5$/);
  const category = within(screen.getByText(authBypass.title).closest("details")!);

  fireEvent.click(category.getAllByText("Intruder로")[0]);

  expect(onSendToIntruder).toHaveBeenCalledWith([authBypass.payloads[0].payload]);
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it("stages every payload in a category for Intruder in one click", async () => {
  vi.stubGlobal("fetch", stubVpnStatus());
  const onSendToIntruder = vi.fn();
  render(<SqlPayloadReference onSendToIntruder={onSendToIntruder} />);
  await screen.findByText(/^10\.10\.14\.5$/);
  const category = within(screen.getByText(authBypass.title).closest("details")!);

  fireEvent.click(category.getByText(/카테고리 전체를 Intruder 후보로 보내기/));

  expect(onSendToIntruder).toHaveBeenCalledWith(authBypass.payloads.map((item) => item.payload));
});
