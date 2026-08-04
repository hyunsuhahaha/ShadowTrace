// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import IntruderPanel from "./IntruderPanel";

afterEach(() => cleanup());

it("blocks running and points to the Request tab when no request is saved yet", () => {
  const onGoToRequest = vi.fn();
  render(<IntruderPanel timeout={30} onGoToRequest={onGoToRequest} />);

  expect(screen.getByText("먼저 저장된 요청이 필요합니다.")).toBeTruthy();
  expect((screen.getByText("먼저 요청을 저장하세요") as HTMLButtonElement).disabled).toBe(true);

  fireEvent.click(screen.getByText("Request 탭 열기 →"));
  expect(onGoToRequest).toHaveBeenCalledTimes(1);
});

it("does not show the missing-request notice once a request is saved", () => {
  render(<IntruderPanel requestId={7} timeout={30} />);

  expect(screen.queryByText("먼저 저장된 요청이 필요합니다.")).toBeNull();
});

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
