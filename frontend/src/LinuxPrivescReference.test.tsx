// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import LinuxPrivescReference from "./LinuxPrivescReference";
import { linuxPrivescCategories } from "./linuxPrivescCommands";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("renders every category as a static, copyable reference", () => {
  render(<LinuxPrivescReference />);

  expect(screen.getByText("SUID / Capabilities")).toBeTruthy();
  expect(screen.getByText("흔한 서비스 설정 파일 위치")).toBeTruthy();
  expect(screen.getByText(
    "cat /etc/postgresql/*/main/pg_hba.conf 2>/dev/null",
  )).toBeTruthy();
  expect(screen.getByText("Redis 설정")).toBeTruthy();
  expect(screen.getByText("MongoDB 설정")).toBeTruthy();
  expect(screen.getByText("제한된 셸/실행 환경 대응")).toBeTruthy();
  expect(screen.getByText("busybox sh")).toBeTruthy();
  expect(screen.getByText("find / -name '.*' -type f 2>/dev/null")).toBeTruthy();
});

it("gives every category a stable id for Command Palette deep-linking", () => {
  const { container } = render(<LinuxPrivescReference />);

  for (const category of linuxPrivescCategories) {
    expect(container.querySelector(`#privesc-${category.id}`), category.id).toBeTruthy();
  }
});

it("copies a command to the clipboard without any network request", async () => {
  const writeText = vi.fn(() => Promise.resolve());
  vi.stubGlobal("navigator", { ...navigator, clipboard: { writeText } });
  const fetcher = vi.fn();
  vi.stubGlobal("fetch", fetcher);
  render(<LinuxPrivescReference />);

  fireEvent.click(screen.getAllByText("복사")[0]);

  await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
  expect(fetcher).not.toHaveBeenCalled();
});

it("hides the shell-input action when no handler is given, and never runs a command on its own", () => {
  render(<LinuxPrivescReference />);

  expect(screen.queryByText("셸에 입력")).toBeNull();
});

it("hands a single command to the caller instead of executing it directly", () => {
  const onSendCommand = vi.fn();
  render(<LinuxPrivescReference onSendCommand={onSendCommand} />);
  const basicInfo = linuxPrivescCategories.find((c) => c.id === "basic-info")!;

  fireEvent.click(screen.getAllByText("셸에 입력")[0]);

  expect(onSendCommand).toHaveBeenCalledTimes(1);
  expect(onSendCommand).toHaveBeenCalledWith(basicInfo.commands[0].command);
});
