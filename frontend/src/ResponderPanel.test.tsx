// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import ResponderPanel from "./ResponderPanel";

afterEach(cleanup);

it("starts Responder on the typed interface, defaulting to tun0", () => {
  const onStartListener = vi.fn();
  render(<ResponderPanel onStartListener={onStartListener} />);
  fireEvent.click(screen.getByText("리스너 준비 (Responder)"));
  expect(onStartListener).toHaveBeenCalledWith("sudo responder -I tun0");
});

it("uses a custom interface when typed", () => {
  const onStartListener = vi.fn();
  render(<ResponderPanel onStartListener={onStartListener} />);
  fireEvent.change(screen.getByLabelText("인터페이스"), { target: { value: "eth0" } });
  fireEvent.click(screen.getByText("리스너 준비 (Responder)"));
  expect(onStartListener).toHaveBeenCalledWith("sudo responder -I eth0");
});
