// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import RecycleBinDecoder from "./RecycleBinDecoder";

afterEach(cleanup);

const FILETIME_UNIX_EPOCH_DIFF_100NS = 116444736000000000n;

function buildIndexFile(
  { size, deletedAt, path }: { size: bigint; deletedAt: Date; path: string },
): string {
  const codeUnits = Array.from(path, (c) => c.charCodeAt(0));
  const buffer = new ArrayBuffer(28 + codeUnits.length * 2);
  const view = new DataView(buffer);
  view.setBigUint64(0, 2n, true);
  view.setBigInt64(8, size, true);
  const filetime = BigInt(deletedAt.getTime()) * 10000n + FILETIME_UNIX_EPOCH_DIFF_100NS;
  view.setBigUint64(16, filetime, true);
  view.setInt32(24, codeUnits.length, true);
  codeUnits.forEach((code, i) => view.setUint16(28 + i * 2, code, true));
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary);
}

it("parses a pasted $I file into path/size/deletion time", async () => {
  render(<RecycleBinDecoder />);
  const base64 = buildIndexFile({
    size: 31_457_280n, deletedAt: new Date("2020-01-01T00:00:00.000Z"),
    path: "C:\\IT\\backup.7z",
  });

  fireEvent.change(screen.getByLabelText("$I 파일 (base64)"), { target: { value: base64 } });

  await waitFor(() => expect(screen.getByText("C:\\IT\\backup.7z")).toBeTruthy());
  expect(screen.getByText("31457280")).toBeTruthy();
  expect(screen.getByText("2020-01-01T00:00:00.000Z")).toBeTruthy();
});

it("shows a failure message for input that isn't a valid $I file", async () => {
  render(<RecycleBinDecoder />);
  fireEvent.change(screen.getByLabelText("$I 파일 (base64)"), {
    target: { value: btoa("not an index file") },
  });
  await waitFor(() => expect(screen.getByText(/파싱 실패/)).toBeTruthy());
});
