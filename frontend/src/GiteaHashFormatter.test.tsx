// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import GiteaHashFormatter from "./GiteaHashFormatter";

afterEach(cleanup);

it("converts hex passwd/salt into a hashcat -m 10900 line", () => {
  render(<GiteaHashFormatter />);
  fireEvent.change(screen.getByLabelText("passwd (hex)"), { target: { value: "aa" } });
  fireEvent.change(screen.getByLabelText("salt (hex)"), { target: { value: "bb" } });

  expect(screen.getByText("sha256:50000:uw==:qg==")).toBeTruthy();
});

it("shows a failure message for invalid hex", () => {
  render(<GiteaHashFormatter />);
  fireEvent.change(screen.getByLabelText("passwd (hex)"), { target: { value: "not-hex" } });
  fireEvent.change(screen.getByLabelText("salt (hex)"), { target: { value: "bb" } });

  expect(screen.getByText(/변환 실패/)).toBeTruthy();
});
