// @vitest-environment jsdom
import {render, screen} from "@testing-library/react";
import {expect, it} from "vitest";
import JobStatus from "./JobStatus";

it("reports stale parallel work", () => {
  render(<JobStatus clock={42000} activeCount={2} run={{templateId: "nmap",
    name: "Nmap", status: "running", startedAt: 1000, lastEventAt: 2000,
    processAlive: true}} />);
  expect(screen.getByText("41s")).toBeTruthy();
  expect(screen.getByRole("alert")).toBeTruthy();
  expect(screen.getByText(/다른 작업 1개/)).toBeTruthy();
});
