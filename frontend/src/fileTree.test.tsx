// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import {
  buildFileTree, FILE_DRAG_MIME, FileTreeView, filterTree, parseTaggedTreeLines,
} from "./fileTree";

afterEach(() => cleanup());

test("buildFileTree reconstructs the original path for both separator styles", () => {
  const windows = buildFileTree(parseTaggedTreeLines(
    "D|C:\\\nD|C:\\Users\nD|C:\\Users\\mike\nD|C:\\Users\\mike\\Desktop\nF|C:\\Users\\mike\\Desktop\\flag.txt"
  ), "\\");
  const flag = windows.children.get("C:")!.children.get("Users")!.children.get("mike")!
    .children.get("Desktop")!.children.get("flag.txt")!;
  expect(flag.path).toBe("C:\\Users\\mike\\Desktop\\flag.txt");

  const linux = buildFileTree(parseTaggedTreeLines(
    "D|/home\nD|/home/bob\nF|/home/bob/.bash_history"
  ), "/");
  const history = linux.children.get("home")!.children.get("bob")!
    .children.get(".bash_history")!;
  expect(history.path).toBe("/home/bob/.bash_history");
});

test("filterTree keeps a name match's whole subtree and its ancestor chain", () => {
  const tree = buildFileTree(parseTaggedTreeLines(
    "D|/home\nD|/home/bob\nD|/home/bob/Desktop\nF|/home/bob/Desktop/flag.txt\n" +
    "F|/home/bob/notes.txt\nD|/home/alice\nF|/home/alice/todo.txt"
  ), "/");
  const filtered = filterTree(tree, "flag");
  const bob = filtered.children.get("home")!.children.get("bob")!;
  expect(bob.children.has("Desktop")).toBe(true);
  expect(bob.children.get("Desktop")!.children.has("flag.txt")).toBe(true);
  expect(bob.children.has("notes.txt")).toBe(false);
  expect(filtered.children.get("home")!.children.has("alice")).toBe(false);
});

test("clicking a file in the tree opens it via onOpenFile with its full path", () => {
  const tree = buildFileTree(parseTaggedTreeLines(
    "D|/home\nD|/home/bob\nD|/home/bob/Desktop\nF|/home/bob/Desktop/flag.txt"
  ), "/");
  const onOpenFile = vi.fn();
  render(<FileTreeView node={tree} onOpenFile={onOpenFile} />);
  fireEvent.click(screen.getByText("home"));
  fireEvent.click(screen.getByText("bob"));
  fireEvent.click(screen.getByText("Desktop"));
  fireEvent.click(screen.getByText("flag.txt"));
  expect(onOpenFile).toHaveBeenCalledWith("/home/bob/Desktop/flag.txt");
});

test("dragging a file sets the shared drag payload with its runId and path", () => {
  const tree = buildFileTree(parseTaggedTreeLines(
    "D|/home\nD|/home/bob\nD|/home/bob/Desktop\nF|/home/bob/Desktop/flag.txt"
  ), "/");
  render(<FileTreeView node={tree} onOpenFile={vi.fn()} runId={7} />);
  fireEvent.click(screen.getByText("home"));
  fireEvent.click(screen.getByText("bob"));
  fireEvent.click(screen.getByText("Desktop"));

  const setData = vi.fn();
  fireEvent.dragStart(screen.getByText("flag.txt"), {
    dataTransfer: {setData, effectAllowed: ""},
  });
  expect(setData).toHaveBeenCalledWith(
    FILE_DRAG_MIME, JSON.stringify(
      {kind: "post-exploitation", runId: 7, path: "/home/bob/Desktop/flag.txt"}));
});

test("a file isn't draggable without a runId (no drag target to promote it into)", () => {
  const tree = buildFileTree(parseTaggedTreeLines(
    "D|/home\nD|/home/bob\nF|/home/bob/flag.txt"
  ), "/");
  render(<FileTreeView node={tree} onOpenFile={vi.fn()} />);
  fireEvent.click(screen.getByText("home"));
  fireEvent.click(screen.getByText("bob"));
  expect(screen.getByText("flag.txt").closest("button")!.draggable).toBe(false);
});

test("searching auto-expands folders down to the match", () => {
  const tree = buildFileTree(parseTaggedTreeLines(
    "D|/home\nD|/home/bob\nD|/home/bob/Desktop\nF|/home/bob/Desktop/flag.txt"
  ), "/");
  render(<FileTreeView node={tree} searchable />);
  const homeDetails = screen.getByText("home").closest("details")!;
  expect(homeDetails.hasAttribute("open")).toBe(false);
  fireEvent.change(screen.getByPlaceholderText("이름으로 검색…"), {target: {value: "flag"}});
  expect(screen.getByText("home").closest("details")!.hasAttribute("open")).toBe(true);
  expect(screen.getByText("Desktop").closest("details")!.hasAttribute("open")).toBe(true);
  expect(screen.getByText("flag.txt")).toBeTruthy();
});
