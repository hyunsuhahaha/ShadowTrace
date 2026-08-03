// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import AsrepRoastPanel from "./AsrepRoastPanel";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const target = { ip: "10.10.10.161" };

it("starts the roast with the typed domain and usersfile, disabled until both are filled", () => {
  const onRoast = vi.fn();
  render(<AsrepRoastPanel target={target} serviceExecutions={[]} evidenceMsg=""
    onRoast={onRoast} onCaptureEvidence={vi.fn()} onOpenHashcat={vi.fn()} />);

  const button = screen.getByText("AS-REP Roasting 시작") as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("도메인"), { target: { value: "htb.local" } });
  fireEvent.change(screen.getByLabelText("사용자명 목록 파일 경로"), {
    target: { value: "/tmp/users.txt" },
  });
  expect(button.disabled).toBe(false);
  fireEvent.click(button);

  expect(onRoast).toHaveBeenCalledWith("htb.local", "/tmp/users.txt");
});

it("fills the usersfile field from a recently derived wordlist on click", () => {
  render(<AsrepRoastPanel target={target} serviceExecutions={[]} evidenceMsg=""
    wordlistSuggestion="/home/kali/OSCP-Workspace/projects/Forest/targets/10.10.10.161/outputs/users.txt"
    onRoast={vi.fn()} onCaptureEvidence={vi.fn()} onOpenHashcat={vi.fn()} />);

  fireEvent.click(screen.getByText("방금 저장한 목록 사용 (users.txt)"));

  expect((screen.getByLabelText("사용자명 목록 파일 경로") as HTMLInputElement).value)
    .toBe("/home/kali/OSCP-Workspace/projects/Forest/targets/10.10.10.161/outputs/users.txt");
});

it("reads the -outputfile hash file and offers the hashcat handoff when it holds a hash", async () => {
  const fetcher = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => Promise.resolve(new Response(
    JSON.stringify({ name: "asrep-hashes.txt", content: "$krb5asrep$23$svc-alfresco@HTB.LOCAL:deadbeef\n" }),
    { headers: { "Content-Type": "application/json" } },
  )));
  vi.stubGlobal("fetch", fetcher);
  const onOpenHashcat = vi.fn();
  render(<AsrepRoastPanel target={target}
    serviceExecutions={[{ id: 7, template_id: "ad-asreproast-impacket", status: "completed" }]}
    evidenceMsg="" onRoast={vi.fn()} onCaptureEvidence={vi.fn()} onOpenHashcat={onOpenHashcat} />);

  fireEvent.click(screen.getByText("output 파일 확인하기"));

  await waitFor(() => expect(screen.getByText(/svc-alfresco@HTB\.LOCAL/)).toBeTruthy());
  expect(fetcher).toHaveBeenCalledWith(
    "/api/executions/7/file?name=asrep-hashes.txt", undefined,
  );
  fireEvent.click(screen.getByText("AS-REP 해시 → hashcat 명령 준비"));
  expect(onOpenHashcat).toHaveBeenCalledOnce();
});

it("shows a plain-language message when no account was roastable", async () => {
  const fetcher = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => Promise.resolve(new Response(
    JSON.stringify({ name: "asrep-hashes.txt", content: "" }),
    { headers: { "Content-Type": "application/json" } },
  )));
  vi.stubGlobal("fetch", fetcher);
  render(<AsrepRoastPanel target={target}
    serviceExecutions={[{ id: 7, template_id: "ad-asreproast-impacket", status: "completed" }]}
    evidenceMsg="" onRoast={vi.fn()} onCaptureEvidence={vi.fn()} onOpenHashcat={vi.fn()} />);

  fireEvent.click(screen.getByText("output 파일 확인하기"));

  await waitFor(() => expect(screen.getByText(/Pre-Auth 미요구 계정이 없거나/)).toBeTruthy());
  expect(screen.queryByText("AS-REP 해시 → hashcat 명령 준비")).toBeNull();
});
