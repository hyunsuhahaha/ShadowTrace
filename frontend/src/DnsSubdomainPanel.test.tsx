// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import DnsSubdomainPanel from "./DnsSubdomainPanel";

afterEach(cleanup);

const target = { ip: "10.10.11.80" };

it("starts the fuzz with the typed domain and wordlist, disabled until both are filled", () => {
  const onFuzz = vi.fn();
  render(<DnsSubdomainPanel target={target} serviceExecutions={[]} evidenceMsg=""
    onFuzz={onFuzz} onCaptureEvidence={vi.fn()} />);

  const button = screen.getByText("탐색 시작") as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("도메인"), { target: { value: "corp.local" } });
  expect(button.disabled).toBe(false);
  fireEvent.click(button);

  expect(onFuzz).toHaveBeenCalledWith(
    "corp.local", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt");
});

it("parses discovered subdomains from a completed run and offers evidence capture", () => {
  const onCaptureEvidence = vi.fn();
  render(<DnsSubdomainPanel target={target} evidenceMsg=""
    serviceExecutions={[{
      id: 4, template_id: "dns-subdomain-enum", status: "completed",
      stdout: "Found: admin.corp.local [10.10.11.5]\nFound: vpn.corp.local\n",
    }]}
    onFuzz={vi.fn()} onCaptureEvidence={onCaptureEvidence} />);

  expect(screen.getByText("admin.corp.local")).toBeTruthy();
  expect(screen.getByText("vpn.corp.local")).toBeTruthy();
  expect(screen.getByText("10.10.11.5")).toBeTruthy();
  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledOnce();
});
