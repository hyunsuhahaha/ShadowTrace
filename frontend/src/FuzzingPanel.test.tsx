// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import FuzzingPanel from "./FuzzingPanel";

afterEach(cleanup);

const target = { ip: "10.10.10.5" };
const service = { port: 80, name: "http" };

it("starts a fuzz run with the currently selected wordlist and no extensions by default", () => {
  const onFuzz = vi.fn();
  render(<FuzzingPanel target={target} service={service} serviceExecutions={[]}
    evidenceMsg="" onFuzz={onFuzz} onCaptureEvidence={vi.fn()} />);

  fireEvent.change(screen.getByRole("combobox"), {
    target: { value: "/usr/share/wordlists/dirb/big.txt" },
  });
  fireEvent.click(screen.getByText("퍼징 시작"));

  expect(onFuzz).toHaveBeenCalledWith("/usr/share/wordlists/dirb/big.txt", "");
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
