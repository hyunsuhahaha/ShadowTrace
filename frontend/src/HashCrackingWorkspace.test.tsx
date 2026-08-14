// @vitest-environment jsdom
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";
import HashCrackingWorkspace, { detectHashMode } from "./HashCrackingWorkspace";

const project = { id: 1, name: "Forest" };
const target = { id: 2, project_id: 1, name: "DC01", ip: "10.10.10.161" };

// Mirrors backend/app/modules/hash_cracking/catalog.py HASH_MODES so the
// detect regexes are exercised exactly as the real catalog defines them.
const hashModes = [
  { id: "ntlm", name: "NTLM (SAM/NTDS, secretsdump)", mode: "1000",
    example: "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
    detect: "^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$" },
  { id: "kerberoast", name: "Kerberoasting (TGS-REP, etype 23)", mode: "13100",
    example: "$krb5tgs$23$*user$REALM$spn*$...", detect: "^\\$krb5tgs\\$23\\$" },
  { id: "asreproast", name: "AS-REP Roasting (etype 23)", mode: "18200",
    example: "$krb5asrep$23$user@REALM:...", detect: "^\\$krb5asrep\\$23\\$" },
  { id: "wpa", name: "WPA-PBKDF2 (PMKID/EAPOL)", mode: "22000",
    example: "WPA*02*...", detect: "^WPA\\*0[12]\\*" },
  { id: "sha256", name: "SHA256 (일반 체크섬)", mode: "1400",
    example: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    detect: "^[0-9a-fA-F]{64}$" },
  { id: "md5", name: "MD5 (구형 웹사이트, 단순 체크섬)", mode: "0",
    example: "5f4dcc3b5aa765d61d8327deb882cf99", detect: "^[0-9a-fA-F]{32}$" },
  { id: "pkzip", name: "PKZIP/ZipCrypto (구형, 압축됨)", mode: "17200",
    example: "$pkzip$1*1*2*0*...*$/pkzip$", detect: "^\\$pkzip\\$" },
];

describe("detectHashMode", () => {
  it("matches each hash family's own catalog pattern", () => {
    expect(detectHashMode(
      "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c", hashModes,
    )).toBe("ntlm");
    expect(detectHashMode("$krb5asrep$23$svc-alfresco@HTB.LOCAL:89bfa3d1", hashModes))
      .toBe("asreproast");
    expect(detectHashMode("WPA*02*deadbeef*aabbcc*112233*essid***", hashModes)).toBe("wpa");
    expect(detectHashMode(
      "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", hashModes,
    )).toBe("sha256");
    expect(detectHashMode("5f4dcc3b5aa765d61d8327deb882cf99", hashModes)).toBe("md5");
  });

  it("reads the first non-empty line and ignores blank leading lines", () => {
    expect(detectHashMode("\n\n$krb5tgs$23$*user$REALM$spn*$deadbeef\n", hashModes))
      .toBe("kerberoast");
  });

  it("returns undefined for unrecognizable or empty input", () => {
    expect(detectHashMode("not a hash", hashModes)).toBeUndefined();
    expect(detectHashMode("", hashModes)).toBeUndefined();
  });
});

function response(body: unknown, status = 200) {
  return Promise.resolve(new Response(
    JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } },
  ));
}

function baseFetcher(extra: (url: string, init?: RequestInit) => Response | undefined) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const handled = extra(url, init);
    if (handled) return Promise.resolve(handled);
    if (url.endsWith("/api/projects")) return response([project]);
    if (url.endsWith("/api/targets")) return response([target]);
    if (url.includes("/hash-cracking/catalog")) return response({
      hash_modes: hashModes,
      wordlists: [{ id: "rockyou", name: "rockyou.txt", path: "/usr/share/wordlists/rockyou.txt",
        installed: true }],
      rules: [], hashcat_installed: true,
    });
    if (url.includes("/hash-cracking?target_id=")) return response([]);
    throw new Error(`Unhandled request: ${url} ${init?.method}`);
  });
}

class FakeEventSource {
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: (() => void) | null = null;
  close() {}
}

function mount(fetcher: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("fetch", fetcher);
  vi.stubGlobal("EventSource", FakeEventSource);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  return render(
    <QueryClientProvider client={client}><HashCrackingWorkspace /></QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  localStorage.clear();
});

it("auto-selects the hash mode from pasted hash text and flags it as detected", async () => {
  mount(baseFetcher(() => undefined));
  const textarea = await screen.findByPlaceholderText(
    "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
  );
  fireEvent.change(textarea, {
    target: { value: "$krb5asrep$23$svc-alfresco@HTB.LOCAL:89bfa3d1" },
  });

  await waitFor(() => expect((screen.getByLabelText(/해시 종류/) as HTMLSelectElement).value)
    .toBe("asreproast"));
  expect(screen.getByText("자동 감지됨")).toBeTruthy();
});

it("swaps the mask field in for the wordlist when a mask-only attack mode is picked", async () => {
  mount(baseFetcher(() => undefined));
  await screen.findByLabelText("공격 모드");

  expect(screen.getByLabelText("워드리스트")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("공격 모드"), { target: { value: "3" } });

  expect(screen.queryByLabelText("워드리스트")).toBeNull();
  expect(screen.getByLabelText(/^마스크/)).toBeTruthy();
});

it("omits the wordlist and sends the mask when starting a brute-force job", async () => {
  let created: any;
  const fetcher = baseFetcher((url, init) => {
    if (url.endsWith("/api/hash-cracking") && init?.method === "POST") {
      created = JSON.parse(init.body as string);
      return new Response(JSON.stringify({ id: 9, ...created }),
        { status: 201, headers: { "Content-Type": "application/json" } });
    }
    if (url.includes("/hash-cracking/9/start") && init?.method === "POST") {
      return new Response(JSON.stringify({ id: 9 }),
        { status: 202, headers: { "Content-Type": "application/json" } });
    }
    return undefined;
  });
  mount(fetcher);
  await screen.findByLabelText("공격 모드");

  fireEvent.change(screen.getByLabelText(/해시 \(한 줄에/), {
    target: { value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" },
  });
  fireEvent.change(screen.getByLabelText("공격 모드"), { target: { value: "3" } });
  fireEvent.change(screen.getByLabelText(/^마스크/), { target: { value: "?u?l?l?l?d?d?d" } });
  fireEvent.click(screen.getByText("크랙 시작"));

  await waitFor(() => expect(created).toBeTruthy());
  expect(created.attack_mode).toBe("3");
  expect(created.mask).toBe("?u?l?l?l?d?d?d");
  expect(created.wordlist_id).toBeUndefined();
});

it("shows the job as running immediately after starting, without waiting for the next history poll", async () => {
  // history is polled every 3s and always returns [] here (matching the
  // real gap right after a job is created: the invalidated query hasn't
  // refetched yet), so this only passes if the status comes from the
  // create/start response itself rather than from `history.data`.
  const fetcher = baseFetcher((url, init) => {
    if (url.endsWith("/api/hash-cracking") && init?.method === "POST") {
      return new Response(JSON.stringify({ id: 9 }),
        { status: 201, headers: { "Content-Type": "application/json" } });
    }
    if (url.includes("/hash-cracking/9/start") && init?.method === "POST") {
      return new Response(JSON.stringify({ id: 9, status: "running" }),
        { status: 202, headers: { "Content-Type": "application/json" } });
    }
    if (url.includes("/hash-cracking/9/output")) {
      return new Response(JSON.stringify({ stdout: "", stderr: "", cracked: [] }),
        { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return undefined;
  });
  mount(fetcher);
  await screen.findByLabelText("공격 모드");
  fireEvent.change(screen.getByLabelText(/해시 \(한 줄에/), {
    target: { value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" },
  });

  fireEvent.click(screen.getByText("크랙 시작"));

  expect(await screen.findByText("실행 중")).toBeTruthy();
});

it("puts the cracked password front and center, with the hash as secondary detail and a copy button", async () => {
  const fetcher = baseFetcher((url) => {
    if (url.includes("/hash-cracking?target_id=")) {
      return new Response(JSON.stringify([{
        id: 4, project_id: 1, target_id: 2, label: "", hash_mode_id: "netntlmv2",
        hash_mode: "5600", hash_type_name: "NetNTLMv2", attack_mode: "0",
        wordlist_id: "rockyou", wordlist2_id: "", rule_id: "", mask: "", hash_count: 1,
        command_display: "", status: "completed", exit_code: 0, cracked_count: 1,
        cancelled: false, error: "", evidence_id: null, created_at: "2026-08-08T04:28:08Z",
      }]), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    if (url.includes("/hash-cracking/4/output")) {
      return new Response(JSON.stringify({ stdout: "", stderr: "", cracked: [
        { hash: "Administrator::RESPONDER:99e51ab52f70937d:aaa:bbb", plain: "badminton" },
      ] }), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    return undefined;
  });
  vi.stubGlobal("navigator", { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } });
  mount(fetcher);

  const plain = await screen.findByText("badminton");
  expect(plain.tagName).toBe("B");
  expect(screen.getByText(/Administrator::RESPONDER/).tagName).toBe("CODE");

  fireEvent.click(screen.getByText("복사"));
  await waitFor(() => expect(screen.getByText("복사됨")).toBeTruthy());
  expect((navigator.clipboard.writeText as ReturnType<typeof vi.fn>))
    .toHaveBeenCalledWith("badminton");
});

it("updates the source credential without asking for its username again", async () => {
  let promoted: any;
  const fetcher = baseFetcher((url, init) => {
    if (url.includes("/hash-cracking?target_id=")) return new Response(JSON.stringify([{
      id: 4, project_id: 1, target_id: 2, label: "", hash_mode_id: "netntlmv2",
      hash_mode: "5600", hash_type_name: "NetNTLMv2", attack_mode: "0",
      wordlist_id: "rockyou", wordlist2_id: "", rule_id: "", mask: "", hash_count: 1,
      command_display: "", status: "completed", exit_code: 0, cracked_count: 1,
      cancelled: false, error: "", evidence_id: null, created_at: "2026-08-08T04:28:08Z",
    }]), { status: 200, headers: { "Content-Type": "application/json" } });
    if (url.includes("/hash-cracking/4/output")) return new Response(JSON.stringify({
      stdout: "", stderr: "", cracked: [{ hash: "Administrator::RESPONDER:a:b", plain: "badminton" }],
    }), { status: 200, headers: { "Content-Type": "application/json" } });
    if (url.endsWith("/api/hash-cracking/4/promote") && init?.method === "POST") {
      promoted = JSON.parse(init.body as string);
      return new Response(JSON.stringify({ id: 9 }),
        { status: 201, headers: { "Content-Type": "application/json" } });
    }
    return undefined;
  });
  vi.stubGlobal("fetch", fetcher);
  vi.stubGlobal("EventSource", FakeEventSource);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><HashCrackingWorkspace embedded
    initialProjectId={1} initialTargetId={2} initialHash="Administrator::RESPONDER:a:b"
    initialMode="netntlmv2" initialCredentialId={9} initialUsername="Administrator" />
  </QueryClientProvider>);

  expect(await screen.findByText("SOURCE CREDENTIAL")).toBeTruthy();
  fireEvent.click(await screen.findByText("Administrator에 연결"));
  await waitFor(() => expect(promoted).toBeTruthy());
  expect(promoted).toMatchObject({ credential_id: 9, secret: "badminton" });
  expect(screen.queryByText("이 평문 비밀번호가 속한 사용자명을 입력하세요.")).toBeNull();
});

it("shows the picked zip's filename even though the native input is cleared right after picking", async () => {
  const fetcher = baseFetcher((url, init) => {
    if (url.endsWith("/api/hash-cracking/zip2john") && init?.method === "POST")
      return new Response(JSON.stringify({ hashes: "$pkzip$1*1*2*0*...*$/pkzip$",
        hash_mode_id: "pkzip", stderr: "" }),
        { headers: { "Content-Type": "application/json" } });
    return undefined;
  });
  mount(fetcher);
  const input = await screen.findByLabelText(/zip 파일에서 해시 추출/) as HTMLInputElement;
  const file = new File(["zip bytes"], "backup.zip", { type: "application/zip" });

  fireEvent.change(input, { target: { files: [file] } });

  // The native input is deliberately cleared right after picking (so the
  // same file can be re-selected later), which used to mean the browser's
  // own "선택된 파일: backup.zip" text never appeared -- this is what
  // stands in for it now.
  expect(await screen.findByText(/backup\.zip/)).toBeTruthy();
  expect(input.value).toBe("");
  await waitFor(() => expect((screen.getByLabelText(/해시 종류/) as HTMLSelectElement).value)
    .toBe("pkzip"));
});

it("persists the form panel width when resized with the scroll wheel", async () => {
  mount(baseFetcher(() => undefined));
  const handle = await screen.findByLabelText("입력 폼 너비 조절");
  expect(handle.getAttribute("aria-valuenow")).toBe("300");

  fireEvent.wheel(handle, { deltaY: -100 });

  expect(handle.getAttribute("aria-valuenow")).toBe("316");
  expect(localStorage.getItem("oscp-crack-form-width")).toBe("316");
});
