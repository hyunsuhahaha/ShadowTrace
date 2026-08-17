// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import {DeleteNodeDialog} from "./graphLeaves";

afterEach(cleanup);

it("confirms node removal inside the app without a native browser dialog", () => {
  const onConfirm = vi.fn();
  const nativeConfirm = vi.spyOn(window, "confirm");
  render(<DeleteNodeDialog label="10.10.10.10" onCancel={vi.fn()} onConfirm={onConfirm} />);

  fireEvent.click(screen.getByRole("button", {name: "노드 제거"}));

  expect(onConfirm).toHaveBeenCalledOnce();
  expect(nativeConfirm).not.toHaveBeenCalled();
});
