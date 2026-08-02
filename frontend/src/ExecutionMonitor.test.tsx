// @vitest-environment jsdom
import {fireEvent, render, screen} from "@testing-library/react";
import {expect, it, vi} from "vitest";
import ExecutionMonitor from "./ExecutionMonitor";
import type {RunState} from "./enumerationModel";

const run: RunState = {
  id: 12,
  templateId: "service-version",
  name: "서비스 버전 확인",
  status: "running",
  startedAt: 10_000,
  lastEventAt: 20_000,
  processAlive: true,
};

it("focuses a run and stops it without selecting the card", () => {
  const onFocus = vi.fn();
  const onStop = vi.fn();
  render(<ExecutionMonitor runs={[run]} focusedId={run.templateId} now={25_000}
    onFocus={onFocus} onStop={onStop} />);

  expect(screen.getByText("15초")).toBeTruthy();
  fireEvent.click(screen.getByLabelText("서비스 버전 확인 작업으로 전환"));
  expect(onFocus).toHaveBeenCalledWith("service-version");

  onFocus.mockClear();
  fireEvent.click(screen.getByText("작업 중단"));
  expect(onStop).toHaveBeenCalledWith("service-version");
  expect(onFocus).not.toHaveBeenCalled();
});

it("warns when a running job has stopped reporting status", () => {
  render(<ExecutionMonitor runs={[run]} now={51_000}
    onFocus={() => undefined} onStop={() => undefined} />);
  expect(screen.getByRole("alert").textContent).toContain("30초 이상");
});
