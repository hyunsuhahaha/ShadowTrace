// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import MetasploitLock from "./MetasploitLock";

afterEach(cleanup);

const targets = [
  { id: 1, name: "Alpha", ip: "10.129.1.1" },
  { id: 2, name: "Beta", ip: "10.129.1.2" },
];

it("renders nothing without a project or a selected target", () => {
  const { container } = render(
    <MetasploitLock targets={targets} onSetLock={vi.fn()} />,
  );
  expect(container.firstChild).toBeNull();
});

it("offers to register the current target when nothing is locked yet", () => {
  const onSetLock = vi.fn();
  render(<MetasploitLock project={{ id: 5, metasploit_target_id: null }}
    targets={targets} targetId={1} onSetLock={onSetLock} />);

  expect(screen.getByText("Metasploit 미사용")).toBeTruthy();
  fireEvent.click(screen.getByText("이 대상에 사용 등록"));

  expect(onSetLock).toHaveBeenCalledWith(1);
});

it("shows the current target as registered and allows clearing it", () => {
  const onSetLock = vi.fn();
  render(<MetasploitLock project={{ id: 5, metasploit_target_id: 1 }}
    targets={targets} targetId={1} onSetLock={onSetLock} />);

  expect(screen.getByText("✓ 이 대상에서 Metasploit 사용 중")).toBeTruthy();
  fireEvent.click(screen.getByText("등록 해제"));

  expect(onSetLock).toHaveBeenCalledWith(null);
});

it("warns when viewing a different target than the one already locked, and requires confirmation to switch", () => {
  const onSetLock = vi.fn();
  const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
  render(<MetasploitLock project={{ id: 5, metasploit_target_id: 1 }}
    targets={targets} targetId={2} onSetLock={onSetLock} />);

  const alert = screen.getByRole("alert");
  expect(alert.textContent).toContain("Alpha");
  expect(alert.textContent).toContain("10.129.1.1");

  fireEvent.click(screen.getByText("변경(주의)"));

  expect(confirmSpy).toHaveBeenCalled();
  expect(onSetLock).not.toHaveBeenCalled();
  confirmSpy.mockRestore();
});

it("changes the lock to the new target once the user confirms the warning", () => {
  const onSetLock = vi.fn();
  vi.spyOn(window, "confirm").mockReturnValue(true);
  render(<MetasploitLock project={{ id: 5, metasploit_target_id: 1 }}
    targets={targets} targetId={2} onSetLock={onSetLock} />);

  fireEvent.click(screen.getByText("변경(주의)"));

  expect(onSetLock).toHaveBeenCalledWith(2);
  vi.restoreAllMocks();
});
