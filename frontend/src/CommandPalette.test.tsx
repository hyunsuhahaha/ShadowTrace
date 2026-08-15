// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import CommandPalette from "./CommandPalette";
import { consumePendingServiceNav } from "./pendingServiceNav";

afterEach(() => {
  cleanup();
  localStorage.clear();
  location.hash = "";
  consumePendingServiceNav();
});

it("shows a hint instead of results when nothing has been used yet", () => {
  render(<CommandPalette onClose={() => {}} />);

  expect(screen.getByText("최근 사용한 항목이 여기 표시됩니다.")).toBeTruthy();
});

it("finds the hidden SQLi reference tab by an English security term", () => {
  render(<CommandPalette onClose={() => {}} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "sql injection" } });

  expect(screen.getByText("SQLi 참고")).toBeTruthy();
});

it("reports no matches for a query that hits nothing", () => {
  render(<CommandPalette onClose={() => {}} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "xyzzyquux" } });

  expect(screen.getByText("일치하는 항목이 없습니다.")).toBeTruthy();
});

it("navigates to the sub-route hash and closes on click, remembering the choice", () => {
  const onClose = vi.fn();
  render(<CommandPalette onClose={onClose} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "repeater" } });
  fireEvent.click(screen.getByText("Repeater"));

  expect(location.hash).toBe("#web/request");
  expect(onClose).toHaveBeenCalledTimes(1);
  expect(JSON.parse(localStorage.getItem("oscp-command-palette-recent")!)).toEqual(["web/request"]);
});

it("surfaces a previously used entry under 최근 사용 when the query is empty", () => {
  localStorage.setItem("oscp-command-palette-recent", JSON.stringify(["web/sqli"]));

  render(<CommandPalette onClose={() => {}} />);

  expect(screen.getByText("최근 사용")).toBeTruthy();
  expect(screen.getByText("SQLi 참고")).toBeTruthy();
});

it("closes on Escape without navigating", () => {
  const onClose = vi.fn();
  render(<CommandPalette onClose={onClose} />);

  fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });

  expect(onClose).toHaveBeenCalledTimes(1);
  expect(location.hash).toBe("");
});

it("navigates to Enumeration and scrolls to the matching panel when the entry has an anchor", async () => {
  vi.useFakeTimers();
  const anchor = document.createElement("div");
  anchor.id = "fuzz-heading";
  anchor.scrollIntoView = vi.fn();
  document.body.appendChild(anchor);
  render(<CommandPalette onClose={() => {}} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "gobuster" } });
  fireEvent.click(screen.getByText("디렉터리·파일 퍼징 (feroxbuster)"));
  vi.runAllTimers();

  expect(location.hash).toBe("#enumeration");
  expect(anchor.scrollIntoView).toHaveBeenCalledOnce();
  anchor.remove();
  vi.useRealTimers();
});

it("stays open and explains why when the target has no matching service for an anchored entry", () => {
  vi.useFakeTimers();
  const onClose = vi.fn();
  render(<CommandPalette onClose={onClose} />);

  // No #dns-subdomain-heading exists anywhere in the DOM — the target this
  // user is on has no DNS service, so DnsSubdomainPanel never mounted.
  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "gobuster dns" } });
  fireEvent.click(screen.getByText("서브도메인 브루트포스 (gobuster dns)"));
  act(() => { vi.runAllTimers(); });

  expect(onClose).not.toHaveBeenCalled();
  expect(screen.getByRole("alert").textContent).toBe(
    "'서브도메인 브루트포스 (gobuster dns)'은(는) 지금 이 대상에 해당 서비스가 없어서 표시되지 않습니다.");
  vi.useRealTimers();
});

it("offers a cross-target service picker when the project has a matching service elsewhere", () => {
  vi.useFakeTimers();
  localStorage.setItem("oscp-workspace-project", "7");
  const onClose = vi.fn();
  const services = [
    { id: 11, target_id: 2, port: 53, protocol: "tcp", name: "domain", product: "", scripts: "" },
  ];
  const targets = [{ id: 2, name: "DC01", ip: "10.10.10.5" }];
  render(<CommandPalette onClose={onClose} services={services} targets={targets} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "gobuster dns" } });
  fireEvent.click(screen.getByText("서브도메인 브루트포스 (gobuster dns)"));
  act(() => { vi.runAllTimers(); });

  // Still open with a picker instead of the dead-end "no matching service" text.
  expect(onClose).not.toHaveBeenCalled();
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.getByText("DC01 · 10.10.10.5")).toBeTruthy();

  fireEvent.click(screen.getByText("DC01 · 10.10.10.5"));

  expect(onClose).toHaveBeenCalledTimes(1);
  expect(location.hash).toBe("#enumeration");
  expect(consumePendingServiceNav()).toEqual({
    targetId: 2, serviceId: 11, anchorId: "dns-subdomain-heading", projectId: 7,
  });
  vi.useRealTimers();
});

it("drops a pending nav queued for a project that is no longer active", () => {
  // Regression test: picking a service, then switching the active project
  // before the destination route mounts and consumes the nav, used to land
  // the OLD project's target/service into the NEW project's Enumeration
  // screen -- consumePendingServiceNav() now checks the nav's project
  // against whatever "oscp-workspace-project" says right now.
  vi.useFakeTimers();
  localStorage.setItem("oscp-workspace-project", "7");
  const onClose = vi.fn();
  const services = [
    { id: 11, target_id: 2, port: 53, protocol: "tcp", name: "domain", product: "", scripts: "" },
  ];
  const targets = [{ id: 2, name: "DC01", ip: "10.10.10.5" }];
  render(<CommandPalette onClose={onClose} services={services} targets={targets} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "gobuster dns" } });
  fireEvent.click(screen.getByText("서브도메인 브루트포스 (gobuster dns)"));
  act(() => { vi.runAllTimers(); });
  fireEvent.click(screen.getByText("DC01 · 10.10.10.5"));

  // User switches the active project before the Enumeration route consumes it.
  localStorage.setItem("oscp-workspace-project", "9");

  expect(consumePendingServiceNav()).toBeUndefined();
  vi.useRealTimers();
});

it("falls back to the plain no-match message when nothing in the project matches either", () => {
  vi.useFakeTimers();
  const onClose = vi.fn();
  render(<CommandPalette onClose={onClose} services={[]} targets={[]} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "gobuster dns" } });
  fireEvent.click(screen.getByText("서브도메인 브루트포스 (gobuster dns)"));
  act(() => { vi.runAllTimers(); });

  expect(onClose).not.toHaveBeenCalled();
  expect(screen.getByRole("alert").textContent).toBe(
    "'서브도메인 브루트포스 (gobuster dns)'은(는) 지금 이 대상에 해당 서비스가 없어서 표시되지 않습니다.");
  vi.useRealTimers();
});

it("lets the picker back out to the search results without navigating", () => {
  vi.useFakeTimers();
  const onClose = vi.fn();
  const services = [
    { id: 11, target_id: 2, port: 53, protocol: "tcp", name: "domain", product: "", scripts: "" },
  ];
  const targets = [{ id: 2, name: "DC01", ip: "10.10.10.5" }];
  render(<CommandPalette onClose={onClose} services={services} targets={targets} />);

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "gobuster dns" } });
  fireEvent.click(screen.getByText("서브도메인 브루트포스 (gobuster dns)"));
  act(() => { vi.runAllTimers(); });
  fireEvent.click(screen.getByText("← 검색으로 돌아가기"));

  expect(screen.getByText("서브도메인 브루트포스 (gobuster dns)")).toBeTruthy();
  expect(onClose).not.toHaveBeenCalled();
  vi.useRealTimers();
});

it("selects and activates a result with ArrowDown + Enter", () => {
  const onClose = vi.fn();
  render(<CommandPalette onClose={onClose} />);
  const dialog = screen.getByRole("dialog");

  fireEvent.change(screen.getByPlaceholderText(/도구나 화면 검색/), { target: { value: "log4shell" } });
  fireEvent.keyDown(dialog, { key: "Enter" });

  expect(location.hash).toBe("#web/log4shell");
  expect(onClose).toHaveBeenCalledTimes(1);
});
