// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import KerbruteEnumPanel from "./KerbruteEnumPanel";

afterEach(cleanup);

const target = { ip: "10.10.10.5" };
const service = { port: 88, name: "kerberos-sec" };

it("starts enumeration with the typed domain and wordlist, disabled until both are filled", () => {
  const onEnum = vi.fn();
  render(<KerbruteEnumPanel target={target} service={service} serviceExecutions={[]}
    evidenceMsg="" onEnum={onEnum} onCaptureEvidence={vi.fn()} />);

  const button = screen.getByText("열거 시작") as HTMLButtonElement;
  expect(button.disabled).toBe(true); // no domain typed yet
  fireEvent.change(screen.getByLabelText("도메인"), { target: { value: "corp.local" } });
  fireEvent.change(screen.getByLabelText("사용자명 워드리스트 경로"), {
    target: { value: "/tmp/users.txt" },
  });
  expect(button.disabled).toBe(false);
  fireEvent.click(button);

  expect(onEnum).toHaveBeenCalledWith("corp.local", "/tmp/users.txt");
});

it("parses kerbrute VALID USERNAME lines from the live run and ignores log noise", () => {
  const stdout = [
    "2026/08/02 12:00:00 >  Using KDC(s):",
    "2026/08/02 12:00:00 >  [+] VALID USERNAME:\t administrator@CORP.LOCAL",
    "2026/08/02 12:00:01 >  [+] VALID USERNAME:\t jdoe@CORP.LOCAL",
    "2026/08/02 12:00:02 >  Done enumerating",
  ].join("\n");
  render(<KerbruteEnumPanel target={target} service={service} serviceExecutions={[]}
    runState={{ templateId: "kerberos-user-enum-kerbrute", status: "running", stdout }}
    evidenceMsg="" onEnum={vi.fn()} onCaptureEvidence={vi.fn()} />);

  expect(screen.getByText("administrator@CORP.LOCAL")).toBeTruthy();
  expect(screen.getByText("jdoe@CORP.LOCAL")).toBeTruthy();
  expect(screen.getByText("2개")).toBeTruthy();
  expect(screen.getByText("열거 중…")).toBeTruthy();
});

it("captures the active execution as evidence, preferring the live run over history", () => {
  const onCaptureEvidence = vi.fn();
  const stdout = "[+] VALID USERNAME:\t administrator@CORP.LOCAL";
  render(<KerbruteEnumPanel target={target} service={service}
    serviceExecutions={[{ id: 1, template_id: "kerberos-user-enum-kerbrute",
      status: "completed", stdout: "stale" }]}
    runState={{ id: 2, templateId: "kerberos-user-enum-kerbrute", status: "completed", stdout }}
    evidenceMsg="" onEnum={vi.fn()} onCaptureEvidence={onCaptureEvidence} />);

  fireEvent.click(screen.getByText("Evidence로 저장"));

  expect(onCaptureEvidence).toHaveBeenCalledWith(
    { id: 2, stdout, stderr: undefined },
    `Kerberos 사용자명 열거 · ${target.ip}:${service.port}`,
  );
});
