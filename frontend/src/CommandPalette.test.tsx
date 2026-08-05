// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import CommandPalette from "./CommandPalette";

afterEach(() => {
  cleanup();
  localStorage.clear();
  location.hash = "";
});

it("shows a hint instead of results when nothing has been used yet", () => {
  render(<CommandPalette onClose={() => {}} />);

  expect(screen.getByText("최근 사용한 항목이 여기 표시됩니다.")).toBeTruthy();
});

it("finds the hidden SQLi reference tab by an English security term", () => {
  render(<CommandPalette onClose={() => {}} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "sql injection" } });

  expect(screen.getByText("SQLi 참고")).toBeTruthy();
});

it("reports no matches for a query that hits nothing", () => {
  render(<CommandPalette onClose={() => {}} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "xyzzyquux" } });

  expect(screen.getByText("일치하는 항목이 없습니다.")).toBeTruthy();
});

it("navigates to the sub-route hash and closes on click, remembering the choice", () => {
  const onClose = vi.fn();
  render(<CommandPalette onClose={onClose} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "repeater" } });
  fireEvent.click(screen.getByText("Repeater"));

  expect(location.hash).toBe("#web/request");
  expect(onClose).toHaveBeenCalledTimes(1);
  expect(JSON.parse(localStorage.getItem("oscp-command-palette-recent")!)).toEqual(["web/request"]);
});

it("surfaces a previously used entry under 최근 사용 when the query is empty", () => {
  localStorage.setItem("oscp-command-palette-recent", JSON.stringify(["web/sqli"]));

  render(<CommandPalette onClose={() => {}} />);

  expect(screen.getByText("최근 사용")).toBeTruthy();
  expect(screen.getByText("SQLi 참고")).toBeTruthy();
});

it("closes on Escape without navigating", () => {
  const onClose = vi.fn();
  render(<CommandPalette onClose={onClose} />);

  fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });

  expect(onClose).toHaveBeenCalledTimes(1);
  expect(location.hash).toBe("");
});

it("selects and activates a result with ArrowDown + Enter", () => {
  const onClose = vi.fn();
  render(<CommandPalette onClose={onClose} />);
  const dialog = screen.getByRole("dialog");

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "log4shell" } });
  fireEvent.keyDown(dialog, { key: "Enter" });

  expect(location.hash).toBe("#web/log4shell");
  expect(onClose).toHaveBeenCalledTimes(1);
});
