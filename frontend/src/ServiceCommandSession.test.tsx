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

const sshClient: ServiceCommand = {
  id: "ssh-client", name: "SSH 수동 접속", description: "SSH 클라이언트를 열고 직접 인증합니다.",
  preview: "ssh -p 22 {username}@10.10.10.10", command: "ssh -p {port} {username}@{host}",
  risk: "low", execution_mode: "interactive",
};

test("offers a one-click username fill per known credential for an interactive username-only profile", () => {
  const review = vi.fn();
  render(<ServiceCommandSession commands={[command, sshClient]} serviceKey="ssh:22"
    targetIp="10.10.10.10" port={22} protocol="tcp"
    credentials={[{username: "postgres"}, {username: "admin"}]}
    onReview={review} />);

  expect(screen.getByText("postgres · SSH 수동 접속")).toBeTruthy();
  fireEvent.click(screen.getByText("admin · SSH 수동 접속"));

  // Switches to the ssh-client profile and fills username, but still stops
  // short of running it -- the operator reviews/edits in the REPL and clicks
  // RUN themselves, same as every other profile.
  expect((screen.getByLabelText("서비스 명령") as HTMLTextAreaElement).value)
    .toBe("ssh -p 22 'admin'@10.10.10.10");
  expect(review).not.toHaveBeenCalled();

  fireEvent.click(screen.getByRole("button", {name: "[ RUN ↵ ]"}));
  expect(review.mock.calls[0][0].variables).toEqual({username: "admin"});
});

test("does not offer quick-connect without a matching interactive username-only profile or without known credentials", () => {
  const {rerender} = render(<ServiceCommandSession commands={[command]} serviceKey="ftp:21"
    targetIp="10.10.10.10" port={21} protocol="tcp"
    credentials={[{username: "anonymous"}]} onReview={vi.fn()} />);
  expect(screen.queryByText(/알려진 계정으로 접속 시도/)).toBeNull();

  rerender(<ServiceCommandSession commands={[command, sshClient]} serviceKey="ssh:22"
    targetIp="10.10.10.10" port={22} protocol="tcp" onReview={vi.fn()} />);
  expect(screen.queryByText(/알려진 계정으로 접속 시도/)).toBeNull();
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
