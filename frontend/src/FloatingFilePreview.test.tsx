// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen, waitFor} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import FloatingFilePreview from "./FloatingFilePreview";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it("opens a movable, eight-way resizable terminal preview with Ctrl+F search", async () => {
  vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(
    "alpha\nbeta alpha", {headers: {"Content-Type": "text/plain"}},
  ))));
  render(<FloatingFilePreview path="scans/result.txt" previewUrl="/preview"
    downloadUrl="/download" onClose={vi.fn()} />);

  const window = screen.getByRole("dialog", {name: "AutoRecon 파일 · scans/result.txt"});
  expect(window.classList.contains("modal")).toBe(false);
  expect(screen.getByTestId("file-preview-drag-handle")).toBeTruthy();
  expect(window.querySelectorAll("[data-resize-direction]")).toHaveLength(8);
  await screen.findByText(/beta alpha/);

  fireEvent.keyDown(document, {key: "f", ctrlKey: true});
  const search = screen.getByRole("searchbox", {name: "파일 내용 검색"});
  fireEvent.change(search, {target: {value: "alpha"}});
  await waitFor(() => expect(screen.getByText("1 / 2")).toBeTruthy());
  expect(window.querySelector(".floatingFilePreview__text")).toBeTruthy();
});
