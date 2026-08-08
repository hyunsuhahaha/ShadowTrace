// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import ResponderPanel from "./ResponderPanel";

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body),
    { status, headers: { "Content-Type": "application/json" } }));
}

function mount(props: Partial<React.ComponentProps<typeof ResponderPanel>> = {}) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ResponderPanel targetId={2} evidenceMsg="" onStartListener={vi.fn()}
        onSendHashToCracking={vi.fn()} onSaveCredential={vi.fn()} {...props} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("starts Responder on the typed interface, defaulting to tun0", () => {
  vi.stubGlobal("fetch", vi.fn(() => response([])));
  const onStartListener = vi.fn();
  mount({ onStartListener });
  fireEvent.click(screen.getByText("리스너 준비 (Responder)"));
  expect(onStartListener).toHaveBeenCalledWith("tun0");
});

it("uses a custom interface when typed", () => {
  vi.stubGlobal("fetch", vi.fn(() => response([])));
  const onStartListener = vi.fn();
  mount({ onStartListener });
  fireEvent.change(screen.getByLabelText("인터페이스"), { target: { value: "eth0" } });
  fireEvent.click(screen.getByText("리스너 준비 (Responder)"));
  expect(onStartListener).toHaveBeenCalledWith("eth0");
});

it("polls captured credentials for this target and masks them until revealed", async () => {
  vi.stubGlobal("fetch", vi.fn((url: string) => {
    expect(url).toBe("/api/targets/2/responder-captures");
    return response([{
      label: "SMB-NTLMv2-SSP-10.129.95.234", username: "Administrator",
      value: "Administrator::RESPONDER:aaa:bbb:ccc", cleartext: false,
      captured_at: "2026-08-08T02:56:55.077317+00:00",
    }]);
  }));
  mount();

  await screen.findByText("Administrator");
  expect(screen.getByText("••••••••")).toBeTruthy();
  expect(screen.queryByText("Administrator::RESPONDER:aaa:bbb:ccc")).toBeNull();

  fireEvent.click(screen.getByText("보기"));
  expect(screen.getByText("Administrator::RESPONDER:aaa:bbb:ccc")).toBeTruthy();
});

it("sends a captured hash to Hash Cracking and saves it to the Credential Store", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response([{
    label: "SMB-NTLMv2-SSP-10.129.95.234", username: "Administrator",
    value: "Administrator::RESPONDER:aaa:bbb:ccc", cleartext: false,
    captured_at: "2026-08-08T02:56:55.077317+00:00",
  }])));
  const onSendHashToCracking = vi.fn();
  const onSaveCredential = vi.fn();
  mount({ onSendHashToCracking, onSaveCredential });

  const capture = await screen.findByText("Administrator");
  const row = capture.closest("tr")!;
  fireEvent.click(within(row).getByText("Hash Cracking으로"));
  fireEvent.click(within(row).getByText("Credential Store에 저장"));

  expect(onSendHashToCracking).toHaveBeenCalledWith("Administrator::RESPONDER:aaa:bbb:ccc");
  expect(onSaveCredential).toHaveBeenCalledWith({
    label: "SMB-NTLMv2-SSP-10.129.95.234", username: "Administrator",
    value: "Administrator::RESPONDER:aaa:bbb:ccc", cleartext: false,
    captured_at: "2026-08-08T02:56:55.077317+00:00",
  });
});

it("does not offer Hash Cracking for a cleartext capture", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response([{
    label: "FTP-Cleartext-ClearText-10.129.95.234", username: "bob",
    value: "hunter2", cleartext: true, captured_at: "2026-08-08T02:56:55.077317+00:00",
  }])));
  mount();

  const capture = await screen.findByText("bob");
  const row = capture.closest("tr")!;
  expect(within(row).queryByText("Hash Cracking으로")).toBeNull();
  expect(within(row).getByText("Credential Store에 저장")).toBeTruthy();
});

it("shows nothing when this target has no captures yet", async () => {
  vi.stubGlobal("fetch", vi.fn(() => response([])));
  mount();

  await waitFor(() => expect(screen.queryByText("캡처된 자격증명")).toBeNull());
});
