// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import OutputColumnExtractor from "./OutputColumnExtractor";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const stdout = [
  "LDAP 10.10.10.161 389 FOREST sebastien",
  "LDAP 10.10.10.161 389 FOREST svc-alfresco",
].join("\n");

it("renders nothing when there is no output to work with", () => {
  const { container } = render(<OutputColumnExtractor executionId={1} stdout="" />);
  expect(container.firstChild).toBeNull();
});

it("extracts the clicked column onward and previews the result", () => {
  const { container } = render(<OutputColumnExtractor executionId={1} stdout={stdout} />);
  fireEvent.click(screen.getByText("속성만 뽑아서 저장"));

  const preview = container.querySelector(".outputExtract__preview") as HTMLElement;
  fireEvent.click(within(preview).getByText("sebastien"));

  expect(screen.getByText("추출된 값 2개")).toBeTruthy();
  const pre = container.querySelector(".outputExtract pre");
  expect(pre?.textContent).toContain("sebastien");
  expect(pre?.textContent).toContain("svc-alfresco");
});

it("defaults to including the rest of the row, narrows to the exact column when unchecked", () => {
  const twoColumnStdout = "FOREST sebastien extra-field\nFOREST svc-alfresco another";
  const { container } = render(
    <OutputColumnExtractor executionId={1} stdout={twoColumnStdout} />,
  );
  fireEvent.click(screen.getByText("속성만 뽑아서 저장"));
  const preview = container.querySelector(".outputExtract__preview") as HTMLElement;
  fireEvent.click(within(preview).getByText("sebastien"));

  expect(container.querySelector(".outputExtract pre")?.textContent)
    .toContain("sebastien extra-field");

  fireEvent.click(screen.getByLabelText("선택한 컬럼부터 끝까지 포함"));
  const narrowed = container.querySelector(".outputExtract pre")?.textContent || "";
  expect(narrowed).not.toContain("extra-field");
  expect(narrowed).toContain("sebastien");
});

it("saves the extracted column as a project file plus Evidence", async () => {
  const fetcher = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => Promise.resolve(new Response(
    JSON.stringify({ id: 9, title: "users.txt" }),
    { headers: { "Content-Type": "application/json" } },
  )));
  vi.stubGlobal("fetch", fetcher);
  const { container } = render(<OutputColumnExtractor executionId={42} stdout={stdout} />);
  fireEvent.click(screen.getByText("속성만 뽑아서 저장"));
  const preview = container.querySelector(".outputExtract__preview") as HTMLElement;
  fireEvent.click(within(preview).getByText("sebastien"));
  fireEvent.change(screen.getByPlaceholderText(/users/), { target: { value: "users" } });
  fireEvent.click(screen.getByText("파일 + Evidence로 저장"));

  await waitFor(() => expect(screen.getByText(
    "프로젝트 폴더에 파일로 저장하고 Evidence에 등록했습니다.",
  )).toBeTruthy());
  expect(fetcher).toHaveBeenCalledWith("/api/executions/42/derive", expect.objectContaining({
    method: "POST",
  }));
  const body = JSON.parse((fetcher.mock.calls[0][1] as RequestInit).body as string);
  expect(body).toEqual({ content: "sebastien\nsvc-alfresco", filename: "users" });
});
