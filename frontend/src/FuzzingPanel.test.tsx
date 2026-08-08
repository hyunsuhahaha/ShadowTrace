// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import FuzzingPanel from "./FuzzingPanel";

afterEach(cleanup);

const target = { ip: "10.10.10.5" };
const service = { port: 80, name: "http" };

it("defaults extensions to a php-biased set so login.php-style hits aren't missed", () => {
  // Reported live on HTB Crocodile: a plain wordlist scan only ever
  // requests bare "/login" and never "/login.php" unless -x is set, and
  // the server 404s the bare path while 200ing the real one — this used
  // to require the operator to remember to type an extension in first.
  const onFuzz = vi.fn();
  render(<FuzzingPanel target={target} service={service} serviceExecutions={[]}
    evidenceMsg="" onFuzz={onFuzz} onCaptureEvidence={vi.fn()} />);

  fireEvent.change(screen.getByRole("combobox"), {
    target: { value: "/usr/share/wordlists/dirb/big.txt" },
  });
  fireEvent.click(screen.getByText("퍼징 시작"));

  expect(onFuzz).toHaveBeenCalledWith("/usr/share/wordlists/dirb/big.txt", "php,html,txt");
});

it("defaults extensions to an aspx-biased set for a Windows target", () => {
  const onFuzz = vi.fn();
  render(<FuzzingPanel target={{ ip: "10.10.10.5", os_guess: "Windows Server 2019" }}
    service={service} serviceExecutions={[]}
    evidenceMsg="" onFuzz={onFuzz} onCaptureEvidence={vi.fn()} />);

  fireEvent.click(screen.getByText("퍼징 시작"));

  expect(onFuzz).toHaveBeenCalledWith(
    "/usr/share/wordlists/dirb/common.txt", "aspx,asp,txt,html");
});

it("still lets the operator clear extensions back out entirely", () => {
  const onFuzz = vi.fn();
  render(<FuzzingPanel target={target} service={service} serviceExecutions={[]}
    evidenceMsg="" onFuzz={onFuzz} onCaptureEvidence={vi.fn()} />);

  fireEvent.change(screen.getByLabelText("확장자"), { target: { value: "" } });
  fireEvent.click(screen.getByText("퍼징 시작"));

  expect(onFuzz).toHaveBeenCalledWith("/usr/share/wordlists/dirb/common.txt", "");
});

it("passes trimmed extensions through when the user fills in gobuster/feroxbuster's -x field", () => {
  const onFuzz = vi.fn();
  render(<FuzzingPanel target={target} service={service} serviceExecutions={[]}
    evidenceMsg="" onFuzz={onFuzz} onCaptureEvidence={vi.fn()} />);

  fireEvent.change(screen.getByLabelText("확장자"), { target: { value: " php,txt,html " } });
  fireEvent.click(screen.getByText("퍼징 시작"));

  expect(onFuzz).toHaveBeenCalledWith(
    "/usr/share/wordlists/dirb/common.txt", "php,txt,html");
});

it("tracks a run under the extensions template id as busy too", () => {
  render(<FuzzingPanel target={target} service={service} serviceExecutions={[]}
    runState={{ templateId: "http-directory-fuzz-ext", status: "running" }}
    evidenceMsg="" onFuzz={vi.fn()} onCaptureEvidence={vi.fn()} />);

  expect(screen.getByText("탐색 중…")).toBeTruthy();
});

it("parses feroxbuster json output from the live run and filters by path", () => {
  const stdout = [
    JSON.stringify({ type: "response", path: "/admin", status: 200,
      content_length: 42, word_count: 3, line_count: 1 }),
    JSON.stringify({ type: "response", path: "/backup.zip", status: 301,
      content_length: 0, word_count: 0, line_count: 0 }),
  ].join("\n");
  render(<FuzzingPanel target={target} service={service} serviceExecutions={[]}
    runState={{ templateId: "http-directory-fuzz", status: "running", stdout }}
    evidenceMsg="" onFuzz={vi.fn()} onCaptureEvidence={vi.fn()} />);

  expect(screen.getByText("/admin")).toBeTruthy();
  expect(screen.getByText("/backup.zip")).toBeTruthy();
  expect(screen.getByText("탐색 중…")).toBeTruthy();

  fireEvent.change(screen.getByLabelText("결과 필터"), { target: { value: "admin" } });

  expect(screen.getByText("/admin")).toBeTruthy();
  expect(screen.queryByText("/backup.zip")).toBeNull();
});

it("excludes results by status code, e.g. hiding 404 noise", () => {
  const stdout = [
    JSON.stringify({ type: "response", path: "/admin", status: 200,
      content_length: 42, word_count: 3, line_count: 1 }),
    JSON.stringify({ type: "response", path: "/nope", status: 404,
      content_length: 10, word_count: 2, line_count: 1 }),
  ].join("\n");
  render(<FuzzingPanel target={target} service={service} serviceExecutions={[]}
    runState={{ templateId: "http-directory-fuzz", status: "running", stdout }}
    evidenceMsg="" onFuzz={vi.fn()} onCaptureEvidence={vi.fn()} />);

  expect(screen.getByText("/nope")).toBeTruthy();

  fireEvent.change(screen.getByLabelText("제외할 Status"), { target: { value: "404,403" } });

  expect(screen.getByText("/admin")).toBeTruthy();
  expect(screen.queryByText("/nope")).toBeNull();
});

it("excludes results by file extension, e.g. hiding static-asset noise", () => {
  const stdout = [
    JSON.stringify({ type: "response", path: "/index.php", status: 200,
      content_length: 42, word_count: 3, line_count: 1 }),
    JSON.stringify({ type: "response", path: "/assets/logo.png", status: 200,
      content_length: 900, word_count: 0, line_count: 0 }),
    JSON.stringify({ type: "response", path: "/assets/main.js", status: 200,
      content_length: 500, word_count: 0, line_count: 0 }),
  ].join("\n");
  render(<FuzzingPanel target={target} service={service} serviceExecutions={[]}
    runState={{ templateId: "http-directory-fuzz", status: "running", stdout }}
    evidenceMsg="" onFuzz={vi.fn()} onCaptureEvidence={vi.fn()} />);

  fireEvent.change(screen.getByLabelText("제외할 확장자"), { target: { value: ".png, js" } });

  expect(screen.getByText("/index.php")).toBeTruthy();
  expect(screen.queryByText("/assets/logo.png")).toBeNull();
  expect(screen.queryByText("/assets/main.js")).toBeNull();
});

it("opens a discovered path against the confirmed hostname instead of the bare IP", () => {
  // A vhost-routed site redirects or refuses bare-IP requests, so an "열기"
  // link built from target.ip alone lands on the wrong (or a stub) page
  // even though the fuzz itself found something real.
  const stdout = JSON.stringify({ type: "response", path: "/admin", status: 200,
    content_length: 1, word_count: 1, line_count: 1 });
  render(<FuzzingPanel target={{ ip: "10.10.10.5", hostname: "unika.htb" }} service={service}
    serviceExecutions={[]}
    runState={{ templateId: "http-directory-fuzz", status: "running", stdout }}
    evidenceMsg="" onFuzz={vi.fn()} onCaptureEvidence={vi.fn()} />);

  expect(screen.getByText("열기").getAttribute("href")).toBe("http://unika.htb:80/admin");
});

it("falls back to the bare IP when no hostname is confirmed yet", () => {
  const stdout = JSON.stringify({ type: "response", path: "/admin", status: 200,
    content_length: 1, word_count: 1, line_count: 1 });
  render(<FuzzingPanel target={target} service={service} serviceExecutions={[]}
    runState={{ templateId: "http-directory-fuzz", status: "running", stdout }}
    evidenceMsg="" onFuzz={vi.fn()} onCaptureEvidence={vi.fn()} />);

  expect(screen.getByText("열기").getAttribute("href")).toBe("http://10.10.10.5:80/admin");
});

it("captures the active execution as evidence, preferring the live run over history", () => {
  const onCaptureEvidence = vi.fn();
  const stdout = JSON.stringify({ type: "response", path: "/x", status: 200,
    content_length: 1, word_count: 1, line_count: 1 });
  render(<FuzzingPanel target={target} service={service}
    serviceExecutions={[{ id: 1, template_id: "http-directory-fuzz", status: "completed",
      stdout: "stale" }]}
    runState={{ id: 2, templateId: "http-directory-fuzz", status: "completed", stdout }}
    evidenceMsg="" onFuzz={vi.fn()} onCaptureEvidence={onCaptureEvidence} />);

  fireEvent.click(screen.getByText("Evidence로 저장"));

  expect(onCaptureEvidence).toHaveBeenCalledWith(
    { id: 2, stdout, stderr: undefined },
    `디렉터리 퍼징 · ${target.ip}:${service.port}`,
  );
});
