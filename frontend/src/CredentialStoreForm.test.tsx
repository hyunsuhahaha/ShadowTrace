// @vitest-environment jsdom
import {fireEvent, render, screen} from "@testing-library/react";
import {expect, it, vi} from "vitest";
import CredentialStoreForm from "./CredentialStoreForm";

const store = {
  saved: {data: []}, domain: "", username: "analyst", password: "secret",
  hint: "", storeSecret: false, sourceKind: "manual", sourceDetail: "",
  setDomain: vi.fn(), setUsername: vi.fn(), setPassword: vi.fn(), setHint: vi.fn(),
  setStoreSecret: vi.fn(), setSourceKind: vi.fn(), setSourceDetail: vi.fn(),
  apply: vi.fn(), save: vi.fn(), remove: vi.fn(), saving: false,
} as any;

it("forwards a single credential check and disables it while running", () => {
  const onCheck = vi.fn();
  const {rerender} = render(<CredentialStoreForm store={store}
    onCheck={onCheck} />);
  fireEvent.click(screen.getByText("NetExec으로 확인"));
  expect(onCheck).toHaveBeenCalledOnce();
  rerender(<CredentialStoreForm store={store} onCheck={onCheck} result={{
    templateId: "smb-check", name: "SMB", status: "running", startedAt: 0,
  }} />);
  expect((screen.getByText("확인 중…") as HTMLButtonElement).disabled).toBe(true);
});
