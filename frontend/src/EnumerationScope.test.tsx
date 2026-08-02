// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, describe, expect, it, vi} from "vitest";
import EnumerationScope from "./EnumerationScope";

vi.mock("./VpnControl", () => ({default: () => <div>VPN</div>}));
afterEach(cleanup);

const project = {id: 1, name: "Lab", description: ""};
const target = {
  id: 2, project_id: 1, name: "DC", ip: "10.10.10.10", hostname: "",
  os_guess: "", vpn: "", notes: "",
};

describe("EnumerationScope", () => {
  it("shows the active scope, tool status, and forwards selections", () => {
    const onSelectProject = vi.fn();
    const onSelectTarget = vi.fn();
    render(<EnumerationScope
      project={project}
      target={target}
      projects={[project, {id: 3, name: "Other", description: ""}]}
      targets={[target]}
      projectId={1}
      targetId={2}
      toolsLoading={false}
      missingTools={[{name: "masscan", install: "apt install masscan"}]}
      onCreateProject={vi.fn()}
      onSelectProject={onSelectProject}
      onCreateTarget={vi.fn()}
      onSelectTarget={onSelectTarget}
      onUpload={vi.fn()}
    />);

    expect(screen.getByText("Lab", {selector: ".target b"})).toBeTruthy();
    expect(screen.getByText("10.10.10.10")).toBeTruthy();
    expect(screen.getByText("미설치: masscan").getAttribute("title"))
      .toBe("apt install masscan");
    fireEvent.change(screen.getByLabelText("프로젝트 선택"), {target: {value: "3"}});
    fireEvent.change(screen.getByLabelText("대상 선택"), {target: {value: "2"}});
    expect(onSelectProject).toHaveBeenCalledWith(3);
    expect(onSelectTarget).toHaveBeenCalledWith(2);
  });

  it("forwards an imported Nmap XML file", () => {
    const onUpload = vi.fn();
    render(<EnumerationScope
      toolsLoading={false}
      missingTools={[]}
      onCreateProject={vi.fn()}
      onSelectProject={vi.fn()}
      onCreateTarget={vi.fn()}
      onSelectTarget={vi.fn()}
      onUpload={onUpload}
    />);
    const file = new File(["<nmaprun />"], "scan.xml", {type: "text/xml"});
    fireEvent.change(screen.getByLabelText("Nmap XML 가져오기"), {
      target: {files: [file]},
    });
    expect(onUpload).toHaveBeenCalledWith(file);
  });
});
