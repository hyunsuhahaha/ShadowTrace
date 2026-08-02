// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import ServiceWorkspace, {type ServiceDraft} from "./ServiceWorkspace";

const draft: ServiceDraft = {product: "", version: "", tags: "", notes: ""};

afterEach(cleanup);

it("updates the controlled service draft and saves it", () => {
  const onDraft = vi.fn();
  const onSave = vi.fn();
  render(<ServiceWorkspace draft={draft} saveState="idle" disabled={false}
    collapsed={false} onDraft={onDraft} onSave={onSave} onToggle={() => undefined} />);

  fireEvent.change(screen.getByLabelText("검토한 서비스 제품"), {
    target: {value: "OpenSSH"},
  });
  expect(onDraft).toHaveBeenCalledWith({...draft, product: "OpenSSH"});
  fireEvent.click(screen.getByText("작업 공간 저장"));
  expect(onSave).toHaveBeenCalledOnce();
});

it("hides the editor when collapsed", () => {
  render(<ServiceWorkspace draft={draft} saveState="idle" disabled
    collapsed onDraft={() => undefined} onSave={() => undefined}
    onToggle={() => undefined} />);
  expect(screen.queryByLabelText("검토한 서비스 제품")).toBeNull();
  expect(screen.getByText("펼치기 ↑")).toBeTruthy();
});
