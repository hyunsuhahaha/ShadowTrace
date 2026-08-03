// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import ChiselPivotPanel from "./ChiselPivotPanel";

afterEach(cleanup);

it("starts the reverse chisel server listener on the typed port", () => {
  const onStartListener = vi.fn();
  render(<ChiselPivotPanel onStartListener={onStartListener} />);
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "9001" } });
  fireEvent.click(screen.getByText("리스너 준비 (chisel server --reverse)"));
  expect(onStartListener).toHaveBeenCalledWith("chisel server -p 9001 --reverse");
});

it("builds a full-SOCKS client command by default", () => {
  render(<ChiselPivotPanel onStartListener={vi.fn()} />);
  fireEvent.change(screen.getByLabelText("Kali IP"), { target: { value: "10.10.14.5" } });
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "8000" } });

  expect(screen.getByText("chisel client 10.10.14.5:8000 R:socks")).toBeTruthy();
});

it("builds a single-port forward client command when that mode is selected", () => {
  render(<ChiselPivotPanel onStartListener={vi.fn()} />);
  fireEvent.change(screen.getByLabelText("Kali IP"), { target: { value: "10.10.14.5" } });
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "8000" } });
  fireEvent.change(screen.getByLabelText("피벗 방식"), { target: { value: "port" } });
  fireEvent.change(screen.getByLabelText("REMOTE_HOST"), { target: { value: "127.0.0.1" } });
  fireEvent.change(screen.getByLabelText("REMOTE_PORT"), { target: { value: "1433" } });

  expect(screen.getByText("chisel client 10.10.14.5:8000 R:1433:127.0.0.1:1433")).toBeTruthy();
});
