// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import S3BucketPanel from "./S3BucketPanel";

afterEach(cleanup);

const target = { ip: "10.10.11.80" };

it("lists buckets on demand and shows the result with an evidence action", () => {
  const onListBuckets = vi.fn();
  const onCaptureEvidence = vi.fn();
  render(<S3BucketPanel target={target} evidenceMsg=""
    serviceExecutions={[{
      id: 1, template_id: "s3-bucket-list", status: "completed",
      stdout: "2024-01-01 00:00:00 the-three.htb\n",
    }]}
    onListBuckets={onListBuckets} onListObjects={vi.fn()}
    onCaptureEvidence={onCaptureEvidence} />);

  fireEvent.click(screen.getByText("버킷 목록 조회"));
  expect(onListBuckets).toHaveBeenCalledOnce();
  expect(screen.getByText(/the-three\.htb/)).toBeTruthy();
  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledOnce();
});

it("only lists objects once a bucket name is typed", () => {
  const onListObjects = vi.fn();
  render(<S3BucketPanel target={target} evidenceMsg="" serviceExecutions={[]}
    onListBuckets={vi.fn()} onListObjects={onListObjects} onCaptureEvidence={vi.fn()} />);

  const button = screen.getByText("버킷 파일 목록 조회") as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("버킷 이름"), { target: { value: "the-three.htb" } });
  expect(button.disabled).toBe(false);
  fireEvent.click(button);
  expect(onListObjects).toHaveBeenCalledWith("the-three.htb");
});
