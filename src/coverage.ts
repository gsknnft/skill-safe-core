import { RULES } from "./rules.js";
import type {
  RuleCoverageEntry,
  SkillRuleId,
  SkillSafeCoverageReport,
  SkillSafeFullReport,
} from "./types.js";

export function createCoverageReport(
  report: SkillSafeFullReport,
): SkillSafeCoverageReport {
  const fired = new Map<SkillRuleId, number>();
  for (const document of report.documents) {
    for (const flag of document.scan.flags) {
      if (!flag.ruleId) continue;
      fired.set(flag.ruleId, (fired.get(flag.ruleId) ?? 0) + 1);
    }
  }

  const rules: RuleCoverageEntry[] = RULES
    .filter((rule) => rule.id)
    .map((rule) => ({
      ruleId: rule.id!,
      ruleName: rule.name ?? rule.id!,
      category: rule.category,
      severity: rule.severity,
      fired: fired.get(rule.id!) ?? 0,
    }));

  const categories: SkillSafeCoverageReport["categories"] = {};
  for (const rule of rules) {
    const current = categories[rule.category] ?? { total: 0, fired: 0 };
    current.total += 1;
    if (rule.fired > 0) current.fired += 1;
    categories[rule.category] = current;
  }

  const firedRules = rules.filter((rule) => rule.fired > 0).length;

  return {
    version: "skill-safe.coverage.v1",
    totalRules: rules.length,
    firedRules,
    neverFiredRules: rules.length - firedRules,
    rules,
    categories,
  };
}

export function formatCoverageReportMarkdown(
  coverage: SkillSafeCoverageReport,
): string {
  const lines = [
    "# skill-safe Rule Coverage",
    "",
    `Rules: ${coverage.firedRules}/${coverage.totalRules} fired`,
    `Never fired: ${coverage.neverFiredRules}`,
    "",
    "## Categories",
    "",
  ];

  for (const [category, value] of Object.entries(coverage.categories).sort()) {
    lines.push(`- ${category}: ${value.fired}/${value.total} fired`);
  }

  const neverFired = coverage.rules.filter((rule) => rule.fired === 0);
  if (neverFired.length) {
    lines.push("", "## Never Fired", "");
    for (const rule of neverFired) {
      lines.push(`- ${rule.ruleId} ${rule.ruleName} (${rule.category})`);
    }
  }

  return `${lines.join("\n")}\n`;
}
