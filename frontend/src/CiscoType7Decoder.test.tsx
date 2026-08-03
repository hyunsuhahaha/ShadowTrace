// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import CiscoType7Decoder from "./CiscoType7Decoder";

afterEach(cleanup);

it("decodes a pasted type 7 value into its plaintext", () => {
  render(<CiscoType7Decoder />);
  fireEvent.change(screen.getByLabelText("Cisco type 7 값"), {
    target: { value: "0242114B0E143F015F5D1E161713" },
  });
  expect(screen.getByText("$uperP@ssword")).toBeTruthy();
});

it("shows a failure message for input that isn't a valid type 7 value", () => {
  render(<CiscoType7Decoder />);
  fireEvent.change(screen.getByLabelText("Cisco type 7 값"), {
    target: { value: "not a type 7 value" },
  });
  expect(screen.getByText(/복호화 실패/)).toBeTruthy();
});
