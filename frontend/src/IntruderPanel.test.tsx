// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import IntruderPanel from "./IntruderPanel";

afterEach(() => cleanup());

it("seeds position 1 with payloads without splitting on commas inside them", () => {
  render(<IntruderPanel timeout={30}
    seed={{ token: 1, values: ["' OR '1'='1'-- -", "' UNION SELECT NULL,NULL,NULL-- -"] }} />);

  expect(screen.getByText("후보 값 · 2개")).toBeTruthy();
  expect(screen.getByText(/쉼표가 포함된 값이 있습니다/)).toBeTruthy();
});

it("appends a later seed to the existing candidates instead of replacing them", () => {
  const { rerender } = render(<IntruderPanel timeout={30}
    seed={{ token: 1, values: ["' OR '1'='1'-- -"] }} />);
  expect(screen.getByText("후보 값 · 1개")).toBeTruthy();

  rerender(<IntruderPanel timeout={30}
    seed={{ token: 2, values: ["' AND SLEEP(5)-- -"] }} />);
  expect(screen.getByText("후보 값 · 2개")).toBeTruthy();
});
