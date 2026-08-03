// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import GppCpasswordDecoder from "./GppCpasswordDecoder";

afterEach(cleanup);

it("decodes a pasted cpassword value into its plaintext", async () => {
  render(<GppCpasswordDecoder />);
  fireEvent.change(screen.getByLabelText("cpassword 값"), {
    target: {
      value: "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ",
    },
  });
  await waitFor(() => expect(screen.getByText("GPPstillStandingStrong2k18")).toBeTruthy());
});

it("shows a failure message for input that isn't a valid cpassword value", async () => {
  render(<GppCpasswordDecoder />);
  fireEvent.change(screen.getByLabelText("cpassword 값"), {
    target: { value: "not a cpassword value" },
  });
  await waitFor(() => expect(screen.getByText(/복호화 실패/)).toBeTruthy());
});
