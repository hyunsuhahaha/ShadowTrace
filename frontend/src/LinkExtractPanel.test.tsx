// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import LinkExtractPanel from "./LinkExtractPanel";

afterEach(cleanup);

const target = { ip: "10.10.11.80" };
const service = { port: 80, name: "http" };

it("extracts from the typed path only, disabled until a path is entered", () => {
  const onFuzz = vi.fn();
  render(<LinkExtractPanel target={target} service={service} serviceExecutions={[]}
    evidenceMsg="" onFuzz={onFuzz} onCaptureEvidence={vi.fn()} onOpenInRequest={vi.fn()} />);

  const button = screen.getByText("링크 추출") as HTMLButtonElement;
  expect(button.disabled).toBe(false);
  fireEvent.change(screen.getByLabelText("경로"), { target: { value: "" } });
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("경로"), {
    target: { value: "/index.php?page=french.html" },
  });
  fireEvent.click(button);

  expect(onFuzz).toHaveBeenCalledWith("/index.php?page=french.html");
});

it("lists discovered links, resolves a relative one to an absolute URL, and offers evidence capture", () => {
  const onOpenInRequest = vi.fn();
  const onCaptureEvidence = vi.fn();
  const nonDefaultPortService = { port: 8080, name: "http" };
  render(<LinkExtractPanel target={target} service={nonDefaultPortService} evidenceMsg=""
    serviceExecutions={[{
      id: 7, template_id: "http-link-extract", status: "completed",
      stdout: "/index.php?page=german.html\ncss/style.css\n#contact-section\n",
    }]}
    onFuzz={vi.fn()} onCaptureEvidence={onCaptureEvidence} onOpenInRequest={onOpenInRequest} />);

  expect(screen.getByText("/index.php?page=german.html")).toBeTruthy();
  fireEvent.click(screen.getByText("Request 탭에 채우기"));
  expect(onOpenInRequest).toHaveBeenCalledWith(
    "http://10.10.11.80:8080/index.php?page=german.html");

  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledOnce();
});

it("normalizes a pasted full URL down to its path before extracting", () => {
  const onFuzz = vi.fn();
  render(<LinkExtractPanel target={target} service={service} serviceExecutions={[]}
    evidenceMsg="" onFuzz={onFuzz} onCaptureEvidence={vi.fn()} onOpenInRequest={vi.fn()} />);

  fireEvent.change(screen.getByLabelText("경로"), {
    target: { value: "http://unika.htb/index.php?page=french.html" },
  });
  fireEvent.click(screen.getByText("링크 추출"));

  expect(onFuzz).toHaveBeenCalledWith("/index.php?page=french.html");
  expect((screen.getByLabelText("경로") as HTMLInputElement).value)
    .toBe("/index.php?page=french.html");
});

it("normalizes a pasted bare-origin URL to the root path", () => {
  const onFuzz = vi.fn();
  render(<LinkExtractPanel target={target} service={service} serviceExecutions={[]}
    evidenceMsg="" onFuzz={onFuzz} onCaptureEvidence={vi.fn()} onOpenInRequest={vi.fn()} />);

  fireEvent.change(screen.getByLabelText("경로"), { target: { value: "http://unika.htb/" } });
  fireEvent.click(screen.getByText("링크 추출"));

  expect(onFuzz).toHaveBeenCalledWith("/");
});

it("tells the user when a completed run produced no links", () => {
  render(<LinkExtractPanel target={target} service={service} evidenceMsg=""
    serviceExecutions={[{
      id: 8, template_id: "http-link-extract", status: "completed", stdout: "",
    }]}
    onFuzz={vi.fn()} onCaptureEvidence={vi.fn()} onOpenInRequest={vi.fn()} />);

  expect(screen.getByText("이 경로에서 찾은 링크가 없습니다.")).toBeTruthy();
});
