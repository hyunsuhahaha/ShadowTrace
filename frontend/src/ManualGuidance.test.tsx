// @vitest-environment jsdom
import {render, screen} from "@testing-library/react";
import {expect, it} from "vitest";
import ManualGuidance from "./ManualGuidance";

it("shows protocol context and manual connection guidance", () => {
  render(<ManualGuidance serviceName="dns" guidance={{title: "DNS 확인",
    command: "dig @10.0.0.1 version.bind chaos txt", steps: ["응답을 기록합니다."],
    accountCandidates: ["analyst"]}} />);
  expect(screen.getByText("이 프로토콜은 추가 인증 문맥이 필요합니다")).toBeTruthy();
  expect(screen.getByText("DNS 확인")).toBeTruthy();
  expect(screen.getByText("analyst 복사")).toBeTruthy();
});
