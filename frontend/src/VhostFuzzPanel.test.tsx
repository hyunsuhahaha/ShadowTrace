// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import VhostFuzzPanel from "./VhostFuzzPanel";

afterEach(cleanup);

const target = { ip: "10.10.11.80" };

it("starts the fuzz with the typed domain and wordlist, disabled until both are filled", () => {
  const onFuzz = vi.fn();
  render(<VhostFuzzPanel target={target} serviceExecutions={[]} evidenceMsg=""
    onFuzz={onFuzz} onCaptureEvidence={vi.fn()} />);

  const button = screen.getByText("퍼징 시작") as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("기본 도메인"), { target: { value: "editor.htb" } });
  expect(button.disabled).toBe(false);
  fireEvent.click(button);

  expect(onFuzz).toHaveBeenCalledWith(
    "editor.htb", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt");
});

it("parses discovered vhosts from a completed run and offers evidence capture", () => {
  const onCaptureEvidence = vi.fn();
  render(<VhostFuzzPanel target={target} evidenceMsg=""
    serviceExecutions={[{
      id: 4, template_id: "http-vhost-fuzz", status: "completed",
      stdout: "wiki                    [Status: 200, Size: 8821, Words: 900, Lines: 210]\n",
    }]}
    onFuzz={vi.fn()} onCaptureEvidence={onCaptureEvidence} />);

  expect(screen.getByText("wiki.<domain>")).toBeTruthy();
  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledOnce();
});
