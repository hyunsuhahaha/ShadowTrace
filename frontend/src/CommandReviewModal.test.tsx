// @vitest-environment jsdom
import {fireEvent, render, screen} from "@testing-library/react";
import {expect, it, vi} from "vitest";
import CommandReviewModal from "./CommandReviewModal";

it("shows the final command and requires an explicit run action", () => {
  const onRun = vi.fn();
  const onSudo = vi.fn();
  const onOutputFilename = vi.fn();
  render(<CommandReviewModal command={{name: "Nmap", preview: "nmap 10.0.0.1", risk: "high"}}
    runWithSudo onSudo={onSudo} outputFilename="" onOutputFilename={onOutputFilename}
    onCancel={() => undefined} onRun={onRun} />);

  expect(screen.getByText("sudo nmap 10.0.0.1")).toBeTruthy();
  expect(screen.getByText(/계정 잠금이나 인증 로그/)).toBeTruthy();
  fireEvent.click(screen.getByText("명령 실행"));
  expect(onRun).toHaveBeenCalledOnce();
  fireEvent.click(screen.getByRole("checkbox"));
  expect(onSudo).toHaveBeenCalledWith(false);
  fireEvent.change(screen.getByPlaceholderText(/hello/), {target: {value: "hello"}});
  expect(onOutputFilename).toHaveBeenCalledWith("hello");
});
