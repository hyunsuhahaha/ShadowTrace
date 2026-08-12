import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { E2E_BACKEND_PORT } from "./ports";
import { SEED_FILE } from "./global-setup";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_URL = `http://127.0.0.1:${E2E_BACKEND_PORT}`;
const FIXTURES = path.join(__dirname, "fixtures");

// Real UI drives the part that proves the SPA actually renders/wires up
// correctly (scan import, runbook apply, evidence upload -- the three
// screens most exposed to regressions from the GraphWorkspace refactor
// happening alongside this suite). Finding/Report authoring is form-heavy
// CRUD already covered by backend unit tests, so it's seeded through the
// same backend the browser is talking to and verified via the real export
// endpoint -- this keeps the spec anchored to one realistic golden path
// instead of re-deriving every free-text field's exact label.
test("scan import -> runbook apply -> evidence -> report export", async ({ page }) => {
  const seed = JSON.parse(readFileSync(SEED_FILE, "utf-8"));

  await page.goto("/");
  await page.getByRole("link", { name: /Scan Center/ }).click();
  await expect(page.getByLabel("대상 선택")).toHaveValue(String(seed.targetId));

  await page
    .getByLabel("기존 Nmap XML 결과 가져오기")
    .setInputFiles(path.join(FIXTURES, "scan.xml"));
  await expect(page.getByText("microsoft-ds")).toBeVisible();

  await page.getByRole("link", { name: /Runbooks/ }).click();
  // getByLabel("Target") is ambiguous here: the Service <select>'s implicit
  // label accessible name includes its "Target 전체" option text, so it
  // substring-matches "Target" too. The Runbook 범위 section always renders
  // Target's <select> first, Service's second (RunbookWorkspace.tsx) --
  // structural position is the stable anchor.
  const runbookScope = page.getByRole("region", { name: "Runbook 범위" });
  await runbookScope.locator("select").first()
    .selectOption({ label: `${seed.targetName} · ${seed.targetIp}` });
  await runbookScope.locator("select").nth(1)
    .selectOption({ label: "445/tcp · microsoft-ds" });
  // The instance view auto-applies the first matching baseline when the
  // selected service has no instances. Wait for that mutation to settle;
  // otherwise its onSuccess can race this tab switch and force the UI back
  // to the execution view.
  await page.locator(".runbookExecution .instanceHeader").waitFor();
  await page.getByRole("button", { name: "추천 Runbooks" }).click();
  // The template name is a heading and the apply control is a sibling button;
  // scope the action to that card instead of assuming the entire card is one
  // accessible button. A successful apply selects the new instance directly.
  const seededRunbook = page.locator(".runbookTemplateRelevant")
    .filter({ hasText: "E2E SMB basics" });
  await seededRunbook.getByText("이 Runbook 적용", { exact: true }).click();
  // The refresh can retain the previously selected baseline instance even
  // though the new instance is present in the sidebar. Select the seeded
  // instance explicitly before asserting its step content.
  await page.getByRole("button", { name: /E2E SMB basics/ }).click();
  await expect(page.getByText("Check anonymous access")).toBeVisible();

  await page.getByRole("link", { name: /Evidence/ }).click();
  await page.getByLabel("증적 파일을 여기에 놓으세요").setInputFiles(
    path.join(FIXTURES, "note.txt"));
  await expect(page.getByText("note.txt")).toBeVisible();
  // Query the same backend the browser just uploaded to, rather than race a
  // live upload response -- the UI assertion above already proves the
  // upload rendered; this just needs the resulting id for the next step.
  // (target_id also has the scan-import's auto-captured nmap Evidence, so
  // filter by title instead of assuming list order/position.)
  const allEvidence: { id: number; title: string }[] = await page
    .request.get(`${BACKEND_URL}/api/evidence?target_id=${seed.targetId}`)
    .then((r) => r.json());
  const evidence = allEvidence.find((item) => item.title === "note.txt");
  expect(evidence).toBeTruthy();

  const findingResponse = await page.request.post(`${BACKEND_URL}/api/findings`, {
    data: {
      project_id: seed.projectId, target_id: seed.targetId,
      title: "Anonymous SMB share access", final_risk: "High",
      risk_override_reason: "E2E fixture: no CVSS vector supplied",
      summary: "Null session allowed share enumeration.",
      evidence: [{ evidence_id: evidence!.id, caption: "E2E evidence proof",
                   include_client: true, include_internal: true }],
    },
  });
  if (!findingResponse.ok()) {
    throw new Error(`create finding failed: ${findingResponse.status()} ${await findingResponse.text()}`);
  }
  const finding = await findingResponse.json();

  const report = await page
    .request.post(`${BACKEND_URL}/api/reports`, {
      data: {
        project_id: seed.projectId, title: "E2E Golden Path Report",
        markdown: "# Assessment\n\nSee findings below.",
        sensitivity_reviewed: true,
      },
    })
    .then((r) => r.json());

  const exported = await page
    .request.get(`${BACKEND_URL}/api/reports/${report.id}/export?format=html&profile=client`)
    .then((r) => r.text());
  expect(exported).toContain(finding.title);
  expect(exported).toContain("E2E evidence proof");
});
