// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import CloudEnumPanel from "./CloudEnumPanel";

afterEach(cleanup);

const target = { ip: "10.10.11.80" };

it("starts the enum with the typed keyword, disabled until one is typed", () => {
  const onEnum = vi.fn();
  render(<CloudEnumPanel target={target} serviceExecutions={[]} evidenceMsg=""
    onEnum={onEnum} onCaptureEvidence={vi.fn()} />);

  const button = screen.getByText("탐색 시작") as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("키워드"), { target: { value: "the-three" } });
  expect(button.disabled).toBe(false);
  fireEvent.click(button);

  expect(onEnum).toHaveBeenCalledWith("the-three");
});

it("shows the raw result and offers evidence capture", () => {
  const onCaptureEvidence = vi.fn();
  render(<CloudEnumPanel target={target} evidenceMsg=""
    serviceExecutions={[{
      id: 7, template_id: "cloud-enum-bucket-discovery", status: "completed",
      stdout: "[+] the-three.s3.amazonaws.com - BUCKET_FOUND\n",
    }]}
    onEnum={vi.fn()} onCaptureEvidence={onCaptureEvidence} />);

  expect(screen.getByText(/the-three\.s3\.amazonaws\.com/)).toBeTruthy();
  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledOnce();
});
