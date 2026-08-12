// @vitest-environment jsdom
import {cleanup, fireEvent, render, screen} from "@testing-library/react";
import {afterEach, expect, test, vi} from "vitest";
import ServiceCommandSession, {commandBinding, type ServiceCommand}
  from "./ServiceCommandSession";

const command: ServiceCommand = {
  id: "service-version", name: "Version detection", description: "Probe service",
  preview: "nmap -Pn -sV -p21 10.10.10.10", command: "nmap -Pn -sV -p{port} {host}",
  risk: "low", execution_mode: "captured",
};

afterEach(cleanup);

test("operator edit is staged as the final command override", () => {
  const review = vi.fn();
  render(<ServiceCommandSession commands={[command]} serviceKey="ftp:21"
    targetIp="10.10.10.10" port={21} protocol="tcp" onReview={review} />);

  fireEvent.change(screen.getByLabelText("서비스 명령"), {
    target: {value: "nmap -Pn -sV --version-all -p21 10.10.10.10"},
  });
  fireEvent.click(screen.getByRole("button", {name: "[ RUN ↵ ]"}));

  expect(screen.getByText("OPERATOR EDIT")).toBeTruthy();
  expect(review.mock.calls[0][0].command_override)
    .toBe("nmap -Pn -sV --version-all -p21 10.10.10.10");
});

test("target, service and engine drift lock execution", () => {
  expect(commandBinding(command.preview, "curl 10.10.10.20:80", "10.10.10.10", 21))
    .toEqual({engine: false, target: false, service: false});
});

test("missing profile context is injected next to the prompt", () => {
  const review = vi.fn();
  const dns: ServiceCommand = {...command, id: "dns-subdomain", name: "DNS enum",
    preview: "gobuster dns -d {domain} -w {wordlist} -r 10.10.10.10:53",
    command: "gobuster dns -d {domain} -w {wordlist} -r {host}:{port}"};
  render(<ServiceCommandSession commands={[dns]} serviceKey="dns:53"
    targetIp="10.10.10.10" port={53} protocol="udp" onReview={review} />);

  expect((screen.getByRole("button", {name: "[ RUN ↵ ]"}) as HTMLButtonElement).disabled)
    .toBe(true);
  fireEvent.change(screen.getByLabelText("domain 컨텍스트"), {target: {value: "lab.htb"}});
  fireEvent.change(screen.getByLabelText("wordlist 컨텍스트"), {
    target: {value: "/usr/share/wordlists/subdomains.txt"},
  });
  fireEvent.click(screen.getByRole("button", {name: "[ RUN ↵ ]"}));

  expect(review.mock.calls[0][0].variables).toEqual({
    domain: "lab.htb", wordlist: "/usr/share/wordlists/subdomains.txt",
  });
});
