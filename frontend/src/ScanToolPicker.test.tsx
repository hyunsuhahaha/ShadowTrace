// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, it, vi} from "vitest";
import ScanToolPicker from "./ScanToolPicker";

afterEach(cleanup);

it("selects a tool and disables masscan behind a VPN tun interface", () => {
  const onSelect = vi.fn();
  render(<ScanToolPicker tool="nmap" masscanBlockedByVpn onSelect={onSelect} />);

  const masscanButton = screen.getByText("masscan").closest("button")!;
  expect(masscanButton.hasAttribute("disabled")).toBe(true);
  expect(screen.getByText("tun0(VPN)에서는 사용할 수 없음")).toBeTruthy();

  fireEvent.click(screen.getByText("Nmap").closest("button")!);
  expect(onSelect).toHaveBeenCalledWith("nmap");
});

it("allows selecting masscan when not blocked", () => {
  const onSelect = vi.fn();
  render(<ScanToolPicker tool="nmap" masscanBlockedByVpn={false} onSelect={onSelect} />);
  fireEvent.click(screen.getByText("masscan").closest("button")!);
  expect(onSelect).toHaveBeenCalledWith("masscan");
});
