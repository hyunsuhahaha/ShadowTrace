// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import ParamFuzzPanel from "./ParamFuzzPanel";

afterEach(cleanup);

const target = { ip: "10.10.11.80" };

it("starts the fuzz with the typed path and wordlist, disabled until both are filled", () => {
  const onFuzz = vi.fn();
  render(<ParamFuzzPanel target={target} serviceExecutions={[]} evidenceMsg=""
    onFuzz={onFuzz} onCaptureEvidence={vi.fn()} />);

  const button = screen.getByText("퍼징 시작") as HTMLButtonElement;
  expect(button.disabled).toBe(false);
  fireEvent.change(screen.getByLabelText("경로"), { target: { value: "" } });
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("경로"), { target: { value: "/index.php" } });
  fireEvent.click(button);

  expect(onFuzz).toHaveBeenCalledWith(
    "/index.php", "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt");
});

it("parses parameters that produced a distinct response and offers evidence capture", () => {
  const onCaptureEvidence = vi.fn();
  render(<ParamFuzzPanel target={target} evidenceMsg=""
    serviceExecutions={[{
      id: 4, template_id: "http-param-fuzz", status: "completed",
      stdout: "page                    [Status: 200, Size: 8821, Words: 900, Lines: 210]\n",
    }]}
    onFuzz={vi.fn()} onCaptureEvidence={onCaptureEvidence} />);

  expect(screen.getByText("?page=")).toBeTruthy();
  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledOnce();
});

it("tells the user when a completed run produced no matching parameters", () => {
  render(<ParamFuzzPanel target={target} evidenceMsg=""
    serviceExecutions={[{
      id: 5, template_id: "http-param-fuzz", status: "completed", stdout: "no matches\n",
    }]}
    onFuzz={vi.fn()} onCaptureEvidence={vi.fn()} />);

  expect(screen.getByText("반응한 파라미터가 없습니다. 경로나 워드리스트를 확인하세요.")).toBeTruthy();
});
