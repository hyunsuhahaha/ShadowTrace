// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import SqlPayloadReference from "./SqlPayloadReference";

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
