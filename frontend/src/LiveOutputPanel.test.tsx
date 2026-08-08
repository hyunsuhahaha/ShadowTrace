// @vitest-environment jsdom
import {cleanup, render, screen} from "@testing-library/react";
import {afterEach, expect, it} from "vitest";
import LiveOutputPanel from "./LiveOutputPanel";

afterEach(cleanup);

it("shows the idle state without a focused run", () => {
  render(<LiveOutputPanel elapsed={0} outcome={null} output="" />);
  expect(screen.getByText("명령 실행 대기")).toBeTruthy();
});

it("reports focused run status, error message and outcome", () => {
  render(<LiveOutputPanel
    run={{templateId: "nmap", name: "Nmap", status: "failed", startedAt: 0,
      lastEventAt: 0, message: "연결 시간 초과", exitCode: 1}}
    elapsed={12} outcome={{tone: "danger", title: "조사가 완료되지 않았습니다",
      detail: "오류 출력을 확인하세요."}}
    output="$ nmap -sV 10.10.10.10\n" />);
  expect(screen.getByText(/Nmap ·/)).toBeTruthy();
  expect(screen.getByText(/종료 코드 1/)).toBeTruthy();
  expect(screen.getByText("연결 시간 초과")).toBeTruthy();
  expect(screen.getByText("조사가 완료되지 않았습니다")).toBeTruthy();
  expect(screen.getByText(/nmap -sV 10.10.10.10/)).toBeTruthy();
});

it("renders a completed ftp-directory-tree run as an expandable tree instead of raw text", () => {
  render(<LiveOutputPanel
    run={{templateId: "ftp-directory-tree", name: "FTP", status: "completed",
      startedAt: 0, lastEventAt: 0}}
    elapsed={3} outcome={null}
    output={"D|pub\nF|pub/readme.txt\n"} />);

  const folder = screen.getByText("pub");
  expect(folder.closest("details")).toBeTruthy();
  expect(screen.queryByText("nmap")).toBeNull();
});

it("renders a completed nfs-export-tree run as an expandable tree too", () => {
  render(<LiveOutputPanel
    run={{templateId: "nfs-export-tree", name: "NFS", status: "completed",
      startedAt: 0, lastEventAt: 0}}
    elapsed={2} outcome={null}
    output={"D|backups\nF|backups/dump.sql\n"} />);

  expect(screen.getByText("backups").closest("details")).toBeTruthy();
});

it("still shows raw text for a still-running ftp-directory-tree, not a partial tree", () => {
  render(<LiveOutputPanel
    run={{templateId: "ftp-directory-tree", name: "FTP", status: "running",
      startedAt: 0, lastEventAt: 0}}
    elapsed={1} outcome={null}
    output={"D|pub\n"} />);

  expect(screen.queryByText("pub")).toBeNull();
  expect(screen.getByText(/D\|pub/)).toBeTruthy();
});
