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
    onCollectBloodhound={onCollectBloodhound} onDcsync={onDcsync}
    onCaptureEvidence={vi.fn()} onFillCredential={vi.fn()} onSaveHash={vi.fn()}
    saveHashMsg="" />);

  expect((screen.getByText("BloodHound 데이터 수집") as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByText("DCSync 시도") as HTMLButtonElement).disabled).toBe(true);

  rerender(<DomainDominancePanel target={target}
    domain="htb.local" username="svc-alfresco" password="s3rvice"
    serviceExecutions={[]} evidenceMsg=""
    onCollectBloodhound={onCollectBloodhound} onDcsync={onDcsync}
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
    onCollectBloodhound={vi.fn()} onDcsync={vi.fn()} onCaptureEvidence={vi.fn()}
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

it("shows a plain-language message when DCSync completed with no dumped accounts", () => {
  render(<DomainDominancePanel target={target}
    domain="htb.local" username="svc-alfresco" password="s3rvice"
    dcsyncRunState={{ id: 5, templateId: "ad-dcsync-secretsdump", status: "completed",
      stdout: "[-] RemoteOperations failed: rpc_s_access_denied\n" }}
    serviceExecutions={[]} evidenceMsg=""
    onCollectBloodhound={vi.fn()} onDcsync={vi.fn()} onCaptureEvidence={vi.fn()}
    onFillCredential={vi.fn()} onSaveHash={vi.fn()} saveHashMsg="" />);

  expect(screen.getByText(/DCSync 권한이 없을 수 있습니다/)).toBeTruthy();
});
