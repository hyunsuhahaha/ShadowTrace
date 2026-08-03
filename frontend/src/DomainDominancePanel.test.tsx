// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import DomainDominancePanel from "./DomainDominancePanel";

afterEach(cleanup);

const target = { ip: "10.10.10.161" };

it("disables both actions until a domain credential is filled in, then triggers them", () => {
  const onCollectBloodhound = vi.fn();
  const onDcsync = vi.fn();
  const { rerender } = render(<DomainDominancePanel target={target}
    domain="htb.local" username="" password="" serviceExecutions={[]} evidenceMsg=""
    onCollectBloodhound={onCollectBloodhound} onDcsync={onDcsync} onGmsa={vi.fn()} onLaps={vi.fn()}
    onCaptureEvidence={vi.fn()} onFillCredential={vi.fn()} onSaveHash={vi.fn()}
    saveHashMsg="" />);

  expect((screen.getByText("BloodHound 데이터 수집") as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByText("DCSync 시도") as HTMLButtonElement).disabled).toBe(true);

  rerender(<DomainDominancePanel target={target}
    domain="htb.local" username="svc-alfresco" password="s3rvice"
    serviceExecutions={[]} evidenceMsg=""
    onCollectBloodhound={onCollectBloodhound} onDcsync={onDcsync} onGmsa={vi.fn()} onLaps={vi.fn()}
    onCaptureEvidence={vi.fn()} onFillCredential={vi.fn()} onSaveHash={vi.fn()}
    saveHashMsg="" />);
  fireEvent.click(screen.getByText("BloodHound 데이터 수집"));
  fireEvent.click(screen.getByText("DCSync 시도"));
  expect(onCollectBloodhound).toHaveBeenCalledOnce();
  expect(onDcsync).toHaveBeenCalledOnce();
});

it("parses dumped hashes from the DCSync run and wires fill/save actions", () => {
  const onFillCredential = vi.fn();
  const onSaveHash = vi.fn();
  const stdout = [
    "[*] Using the DRSUAPI method to get NTDS.DIT secrets",
    "Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::",
  ].join("\n");
  render(<DomainDominancePanel target={target}
    domain="htb.local" username="svc-alfresco" password="s3rvice"
    dcsyncRunState={{ id: 5, templateId: "ad-dcsync-secretsdump", status: "completed", stdout }}
    serviceExecutions={[]} evidenceMsg=""
    onCollectBloodhound={vi.fn()} onDcsync={vi.fn()} onGmsa={vi.fn()} onLaps={vi.fn()} onCaptureEvidence={vi.fn()}
    onFillCredential={onFillCredential} onSaveHash={onSaveHash} saveHashMsg="" />);

  expect(screen.getByText("Administrator")).toBeTruthy();
  expect(screen.getByText("1개")).toBeTruthy();
  fireEvent.click(screen.getByText("자격증명 칸에 채우기"));
  expect(onFillCredential).toHaveBeenCalledWith(
    "Administrator", "32693b11e6aa90eb43d32c72a07ceea6",
  );
  fireEvent.click(screen.getByText("Credential로 저장"));
  expect(onSaveHash).toHaveBeenCalledWith(
    "Administrator", "32693b11e6aa90eb43d32c72a07ceea6",
  );
});

it("triggers the gMSA lookup and offers evidence capture on a completed run", () => {
  const onGmsa = vi.fn();
  const onCaptureEvidence = vi.fn();
  const { rerender } = render(<DomainDominancePanel target={target}
    domain="htb.local" username="alfred" password="basketball"
    serviceExecutions={[]} evidenceMsg=""
    onCollectBloodhound={vi.fn()} onDcsync={vi.fn()} onGmsa={onGmsa} onLaps={vi.fn()}
    onCaptureEvidence={onCaptureEvidence} onFillCredential={vi.fn()} onSaveHash={vi.fn()}
    saveHashMsg="" />);
  fireEvent.click(screen.getByText("gMSA 비밀번호 추출"));
  expect(onGmsa).toHaveBeenCalledOnce();

  rerender(<DomainDominancePanel target={target}
    domain="htb.local" username="alfred" password="basketball"
    gmsaRunState={{ id: 8, templateId: "ad-gmsa-password-netexec", status: "completed",
      stdout: "Account: ANSIBLE_DEV$ NTLM: 1c37d00093dc2a5f25176bf2d474afdc\n" }}
    serviceExecutions={[]} evidenceMsg=""
    onCollectBloodhound={vi.fn()} onDcsync={vi.fn()} onGmsa={onGmsa} onLaps={vi.fn()}
    onCaptureEvidence={onCaptureEvidence} onFillCredential={vi.fn()} onSaveHash={vi.fn()}
    saveHashMsg="" />);
  expect(screen.getByText(/ANSIBLE_DEV\$/)).toBeTruthy();
  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledOnce();
});

it("triggers the LAPS lookup and offers evidence capture on a completed run", () => {
  const onLaps = vi.fn();
  const onCaptureEvidence = vi.fn();
  const { rerender } = render(<DomainDominancePanel target={target}
    domain="htb.local" username="t.hackett" password="Password123"
    serviceExecutions={[]} evidenceMsg=""
    onCollectBloodhound={vi.fn()} onDcsync={vi.fn()} onGmsa={vi.fn()} onLaps={onLaps}
    onCaptureEvidence={onCaptureEvidence} onFillCredential={vi.fn()} onSaveHash={vi.fn()}
    saveHashMsg="" />);
  fireEvent.click(screen.getByText("LAPS 비밀번호 조회"));
  expect(onLaps).toHaveBeenCalledOnce();

  rerender(<DomainDominancePanel target={target}
    domain="htb.local" username="t.hackett" password="Password123"
    lapsRunState={{ id: 9, templateId: "ad-laps-password-netexec", status: "completed",
      stdout: "DC01$ Password: aB3!xyz\n" }}
    serviceExecutions={[]} evidenceMsg=""
    onCollectBloodhound={vi.fn()} onDcsync={vi.fn()} onGmsa={vi.fn()} onLaps={onLaps}
    onCaptureEvidence={onCaptureEvidence} onFillCredential={vi.fn()} onSaveHash={vi.fn()}
    saveHashMsg="" />);
  expect(screen.getByText(/aB3!xyz/)).toBeTruthy();
  fireEvent.click(screen.getByText("Evidence로 저장"));
  expect(onCaptureEvidence).toHaveBeenCalledOnce();
});

it("shows a plain-language message when DCSync completed with no dumped accounts", () => {
  render(<DomainDominancePanel target={target}
    domain="htb.local" username="svc-alfresco" password="s3rvice"
    dcsyncRunState={{ id: 5, templateId: "ad-dcsync-secretsdump", status: "completed",
      stdout: "[-] RemoteOperations failed: rpc_s_access_denied\n" }}
    serviceExecutions={[]} evidenceMsg=""
    onCollectBloodhound={vi.fn()} onDcsync={vi.fn()} onGmsa={vi.fn()} onLaps={vi.fn()} onCaptureEvidence={vi.fn()}
    onFillCredential={vi.fn()} onSaveHash={vi.fn()} saveHashMsg="" />);

  expect(screen.getByText(/DCSync 권한이 없을 수 있습니다/)).toBeTruthy();
});
