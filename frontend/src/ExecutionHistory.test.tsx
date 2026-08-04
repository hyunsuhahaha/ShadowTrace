// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import ExecutionHistory, {type ExecutionRecord} from "./ExecutionHistory";

afterEach(cleanup);

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
    onView={() => undefined} onOpen={onOpen} onStop={() => undefined}
    onDelete={() => undefined} />);

  fireEvent.click(screen.getByText(/#9 smb-enum/));

  expect(onOpen).toHaveBeenCalledWith(9);
  expect(screen.getByText("1개")).toBeTruthy();
});

it("shows saved output and stops a running execution", () => {
  const onStop = vi.fn();
  render(<ExecutionHistory executions={[execution]} view="detail"
    selected={execution} detail={{status: "running", stdout: "share list"}}
    onView={() => undefined} onOpen={() => undefined} onStop={onStop}
    onDelete={() => undefined} />);

  expect(screen.getByText("share list")).toBeTruthy();
  fireEvent.click(screen.getByText("실행 중단"));
  expect(onStop).toHaveBeenCalledOnce();
});

it("does not offer to delete a still-running execution, but does once it finishes", () => {
  const onDelete = vi.fn();
  const finished = {...execution, id: 10, status: "completed"};
  render(<ExecutionHistory executions={[execution, finished]} view="list"
    onView={() => undefined} onOpen={() => undefined} onStop={() => undefined}
    onDelete={onDelete} />);

  expect(screen.queryAllByText("삭제")).toHaveLength(1);
  fireEvent.click(screen.getByText("삭제"));
  expect(onDelete).toHaveBeenCalledWith(10);
});

it("offers to delete a finished execution from the detail view", () => {
  const onDelete = vi.fn();
  const finished = {...execution, status: "completed"};
  render(<ExecutionHistory executions={[finished]} view="detail"
    selected={finished} detail={{status: "completed", stdout: "share list"}}
    onView={() => undefined} onOpen={() => undefined} onStop={() => undefined}
    onDelete={onDelete} />);

  expect(screen.queryByText("실행 중단")).toBeNull();
  fireEvent.click(screen.getByText("삭제"));
  expect(onDelete).toHaveBeenCalledWith(9);
});
