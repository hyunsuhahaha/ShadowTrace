// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import WindowsPrivescReference from "./WindowsPrivescReference";
import { windowsPrivescCategories } from "./windowsPrivescCommands";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("renders every category as a static, copyable reference", () => {
  render(<WindowsPrivescReference />);

  expect(screen.getByText("PowerShell 히스토리·저장된 자격증명")).toBeTruthy();
  expect(screen.getByText(
    "type (Get-PSReadlineOption).HistorySavePath",
  )).toBeTruthy();
  expect(screen.getByText("서비스 권한·예약 작업")).toBeTruthy();
  expect(screen.getByText("schtasks /query /fo LIST /v")).toBeTruthy();
});

it("gives every category a stable id for Command Palette deep-linking", () => {
  const { container } = render(<WindowsPrivescReference />);

  for (const category of windowsPrivescCategories) {
    expect(container.querySelector(`#winprivesc-${category.id}`), category.id).toBeTruthy();
  }
});

it("copies a command to the clipboard without any network request", async () => {
  const writeText = vi.fn(() => Promise.resolve());
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  render(<WindowsPrivescReference />);

  fireEvent.click(screen.getAllByText("복사")[0]);

  await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
  expect(fetcher).not.toHaveBeenCalled();
});

it("hides the shell-input action when no handler is given, and never runs a command on its own", () => {
  render(<WindowsPrivescReference />);

  expect(screen.queryByText("셸에 입력")).toBeNull();
});

it("hands a single command to the caller instead of executing it directly", () => {
  const onSendCommand = vi.fn();
  render(<WindowsPrivescReference onSendCommand={onSendCommand} />);
  const basicInfo = windowsPrivescCategories.find((c) => c.id === "win-basic-info")!;

  fireEvent.click(screen.getAllByText("셸에 입력")[0]);

  expect(onSendCommand).toHaveBeenCalledTimes(1);
  expect(onSendCommand).toHaveBeenCalledWith(basicInfo.commands[0].command);
});
