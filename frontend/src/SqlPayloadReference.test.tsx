// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import SqlPayloadReference from "./SqlPayloadReference";
import { sqlPayloadCategories } from "./sqlPayloads";

const authBypass = sqlPayloadCategories.find((category) => category.id === "auth-bypass")!;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("renders every payload category as a copyable reference, not an executable form", () => {
  render(<SqlPayloadReference />);

  expect(screen.getByText("UNION 기반 추출")).toBeTruthy();
  expect(screen.getByText("MSSQL xp_cmdshell")).toBeTruthy();
  expect(screen.queryByRole("textbox")).toBeNull();
});

it("copies a payload to the clipboard without sending any network request", async () => {
  const writeText = vi.fn(() => Promise.resolve());
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  render(<SqlPayloadReference />);

  fireEvent.click(screen.getAllByText("복사")[0]);

  await vi.waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
  expect(fetcher).not.toHaveBeenCalled();
});

it("hides the Intruder handoff buttons when no handler is given", () => {
  render(<SqlPayloadReference />);

  expect(screen.queryByText("Intruder로")).toBeNull();
  expect(screen.queryByText(/Intruder 후보로 보내기/)).toBeNull();
});

it("stages a single payload for Intruder without sending any network request", () => {
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  const onSendToIntruder = vi.fn();
  render(<SqlPayloadReference onSendToIntruder={onSendToIntruder} />);
  const category = within(screen.getByText(authBypass.title).closest("details")!);

  fireEvent.click(category.getAllByText("Intruder로")[0]);

  expect(onSendToIntruder).toHaveBeenCalledWith([authBypass.payloads[0].payload]);
  expect(fetcher).not.toHaveBeenCalled();
});

it("stages every payload in a category for Intruder in one click", () => {
  const onSendToIntruder = vi.fn();
  render(<SqlPayloadReference onSendToIntruder={onSendToIntruder} />);
  const category = within(screen.getByText(authBypass.title).closest("details")!);

  fireEvent.click(category.getByText(/카테고리 전체를 Intruder 후보로 보내기/));

  expect(onSendToIntruder).toHaveBeenCalledWith(authBypass.payloads.map((item) => item.payload));
});
