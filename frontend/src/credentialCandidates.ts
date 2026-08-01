export type AttackType = "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb";
export type ProcessingRule = {
  type: "prefix" | "suffix" | "lower" | "upper" | "url_encode" | "base64" | "replace" | "regex_replace";
  value?: string;
  replacement?: string;
};
export type PayloadPosition = {
  name: string;
  candidates: string[];
  rules?: ProcessingRule[];
};

export function parseCandidates(input: string, deduplicate = true): string[] {
  const values = input.split(/\r?\n|,/).map((value) => value.trim()).filter(Boolean)
    .flatMap((value) => {
      const match = value.match(/^(-?\d+)\.\.(-?\d+)$/);
      if (!match) return value;
      const start = Number(match[1]), end = Number(match[2]), step = start <= end ? 1 : -1;
      if (Math.abs(end - start) > 9999) return value;
      return Array.from({ length: Math.abs(end - start) + 1 }, (_, index) => String(start + index * step));
    });
  return deduplicate ? [...new Set(values)] : values;
}

export function processCandidate(value: string, rules: ProcessingRule[] = []): string {
  return rules.reduce((current, rule) => {
    if (rule.type === "prefix") return (rule.value || "") + current;
    if (rule.type === "suffix") return current + (rule.value || "");
    if (rule.type === "lower") return current.toLowerCase();
    if (rule.type === "upper") return current.toUpperCase();
    if (rule.type === "url_encode") return encodeURIComponent(current);
    if (rule.type === "base64") return btoa(unescape(encodeURIComponent(current)));
    if (rule.type === "replace") return current.split(rule.value || "").join(rule.replacement || "");
    if (rule.type === "regex_replace")
      return current.replace(new RegExp(rule.value || "", "g"), rule.replacement || "");
    return current;
  }, value.trim());
}

export function requestCount(type: AttackType, positions: PayloadPosition[]): number {
  const lengths = positions.map((position) => position.candidates.length);
  if (!lengths.length || lengths.some((length) => length === 0)) return 0;
  if (type === "sniper") return lengths.reduce((sum, length) => sum + length, 0);
  if (type === "battering_ram") return lengths[0];
  if (type === "pitchfork") return Math.min(...lengths);
  return lengths.reduce((product, length) => product * length, 1);
}

export function previewCombinations(
  type: AttackType,
  positions: PayloadPosition[],
  limit = 5,
): Record<string, string>[] {
  const processed = positions.map((position) => ({
    ...position,
    candidates: position.candidates.map((value) => processCandidate(value, position.rules)),
  }));
  if (!processed.length || processed.some((position) => !position.candidates.length)) return [];
  const base = Object.fromEntries(processed.map((position) => [position.name, `{{${position.name}}}`]));
  if (type === "sniper")
    return processed.flatMap((position) =>
      position.candidates.map((value) => ({ ...base, [position.name]: value })),
    ).slice(0, limit);
  if (type === "battering_ram")
    return processed[0].candidates.slice(0, limit).map((value) =>
      Object.fromEntries(processed.map((position) => [position.name, value])),
    );
  if (type === "pitchfork")
    return Array.from({ length: Math.min(...processed.map((position) => position.candidates.length)) },
      (_, index) => Object.fromEntries(processed.map((position) => [position.name, position.candidates[index]])),
    ).slice(0, limit);
  let combinations: Record<string, string>[] = [{}];
  for (const position of processed)
    combinations = combinations.flatMap((combination) =>
      position.candidates.map((value) => ({ ...combination, [position.name]: value })),
    ).slice(0, limit);
  return combinations;
}
