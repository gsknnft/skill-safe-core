import { RULES } from "./rules.js";
import type { SkillRuleId, SkillSafeFullReport, SuppressionAuditFinding, SuppressionAuditReport } from "./types.js";



const BUILT_IN_RULE_IDS = new Set(
  RULES.map((rule) => rule.id).filter((id): id is SkillRuleId => Boolean(id)),
);

export function auditSuppressions(report: SkillSafeFullReport): SuppressionAuditReport {
  const findings: SuppressionAuditFinding[] = [];

  for (const document of report.documents) {
    const activeRuleIds = new Set(
      document.scan.flags
        .map((flag) => flag.ruleId)
        .filter((id): id is SkillRuleId => Boolean(id)),
    );

    for (const suppression of document.scan.suppressions) {
      if (!BUILT_IN_RULE_IDS.has(suppression.ruleId as SkillRuleId)) {
        findings.push({
          documentId: document.id,
          ruleId: suppression.ruleId,
          line: suppression.line,
          reason: suppression.reason,
          issue: "invalid-rule",
        });
        continue;
      }

      if (!activeRuleIds.has(suppression.ruleId as SkillRuleId)) {
        findings.push({
          documentId: document.id,
          ruleId: suppression.ruleId,
          line: suppression.line,
          reason: suppression.reason,
          issue: "unused-suppression",
        });
      }
    }
  }

  return {
    version: "skill-safe.suppression-audit.v1",
    ok: findings.length === 0,
    invalid: findings.filter((finding) => finding.issue === "invalid-rule").length,
    unused: findings.filter((finding) => finding.issue === "unused-suppression").length,
    findings,
  };
}
