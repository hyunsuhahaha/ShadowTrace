// @vitest-environment jsdom
import {fireEvent, render, screen} from "@testing-library/react";
import {expect, it, vi} from "vitest";
import ExecutionHistory, {type ExecutionRecord} from "./ExecutionHistory";

const execution: ExecutionRecord = {
  id: 9,
  template_id: "smb-enum",
  status: "running",
  command: "smbclient -L //10.10.10.10",
  started_at: "2026-08-02T12:00:00Z",
};

it("opens a selected execution from the history list", () => {
  const onOpen = vi.fn();
  render(<ExecutionHistory executions={[execution]} view="list"
    onView={() => undefined} onOpen={onOpen} onStop={() => undefined} />);

  fireEvent.click(screen.getByText(/#9 smb-enum/));

  expect(onOpen).toHaveBeenCalledWith(9);
  expect(screen.getByText("1개")).toBeTruthy();
});

it("shows saved output and stops a running execution", () => {
  const onStop = vi.fn();
  render(<ExecutionHistory executions={[execution]} view="detail"
    selected={execution} detail={{status: "running", stdout: "share list"}}
    onView={() => undefined} onOpen={() => undefined} onStop={onStop} />);

  expect(screen.getByText("share list")).toBeTruthy();
  fireEvent.click(screen.getByText("실행 중단"));
  expect(onStop).toHaveBeenCalledOnce();
});
