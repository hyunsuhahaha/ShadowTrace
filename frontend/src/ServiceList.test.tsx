// @vitest-environment jsdom
import {fireEvent, render, screen} from "@testing-library/react";
import {expect, it, vi} from "vitest";
import ServiceList from "./ServiceList";
import type {Service} from "./enumerationModel";

const service = {
  id: 7,
  port: 445,
  protocol: "tcp",
  name: "smb",
  product: "Samba",
  version: "4.19",
} as Service;

it("shows service identity and selects the clicked service", () => {
  const onSelect = vi.fn();
  render(<ServiceList services={[service]} selectedId={7} onSelect={onSelect} />);

  expect(screen.getByText("1개 열림")).toBeTruthy();
  expect(screen.getByText("Samba 4.19")).toBeTruthy();
  fireEvent.click(screen.getByRole("button"));

  expect(onSelect).toHaveBeenCalledWith(7);
});

it("shows the scan guidance when no services exist", () => {
  render(<ServiceList services={[]} onSelect={() => undefined} />);
  expect(screen.getByText(/Nmap XML 스캔을 가져오세요/)).toBeTruthy();
});
