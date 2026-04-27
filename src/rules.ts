/**
 * skill-safe rule definitions.
 *
 * CONTRIBUTING: add rules to the relevant section below.
 * Each rule needs:
 *   - pattern   RegExp  — what to match (use /i for case-insensitive where appropriate)
 *   - severity  "caution" | "danger"
 *   - category  SanitizationCategory
 *   - description  string  — human-readable explanation shown to the user
 *
 * Guidelines:
 *   - Prefer "danger" for patterns that actively subvert agent behavior or exfiltrate data.
 *   - Prefer "caution" for patterns that are sometimes legitimate but warrant a second look.
 *   - Keep patterns specific enough to avoid false-positives on normal skill descriptions.
 *   - Add a comment above the rule explaining *why* it's flagged if it's non-obvious.
 */

export type SanitizationCategory =
  | "prompt-injection"
  | "identity-hijack"
  | "jailbreak"
  | "data-exfiltration"
  | "script-injection"
  | "format-injection"
  | "excessive-claims"
  | "hidden-content"
  | "hitl-bypass"
  | "package-age"
  | "missing-provenance";

export type SanitizationSeverity = "caution" | "danger";

export type SkillRuleId = `SS${string}`;

export type RuleDefinition = {
  /** Stable rule identifier. Built-in rules use SS001-style IDs. */
  id?: SkillRuleId;
  /** Stable short name for reports, SARIF, docs, and future suppressions. */
  name?: string;
  pattern: RegExp;
  severity: SanitizationSeverity;
  category: SanitizationCategory;
  description: string;
  owasp?: string[];
  mitreAtlas?: string[];
  nistAiRmf?: string[];
};

export type GovernanceMappings = {
  owasp: string[];
  mitreAtlas: string[];
  nistAiRmf: string[];
};

export const CATEGORY_GOVERNANCE_MAPPINGS: Record<
  SanitizationCategory,
  GovernanceMappings
> = {
  "prompt-injection": {
    owasp: [
      "AST01 Malicious Skills",
      "LLM01 Prompt Injection",
    ],
    mitreAtlas: ["AML.T0051 Prompt Injection", "AML.T0054 Indirect Prompt Injection"],
    nistAiRmf: ["Measure", "Manage"],
  },
  "identity-hijack": {
    owasp: ["AST01 Malicious Skills", "AST04 Insecure Metadata"],
    mitreAtlas: ["AML.T0051 Prompt Injection"],
    nistAiRmf: ["Map", "Measure"],
  },
  jailbreak: {
    owasp: ["AST01 Malicious Skills", "LLM01 Prompt Injection"],
    mitreAtlas: ["AML.T0051 Prompt Injection"],
    nistAiRmf: ["Measure", "Manage"],
  },
  "data-exfiltration": {
    owasp: ["AST01 Malicious Skills", "AST03 Over-Privileged Skills"],
    mitreAtlas: ["Exfiltration"],
    nistAiRmf: ["Measure", "Manage"],
  },
  "script-injection": {
    owasp: ["AST01 Malicious Skills", "AST04 Insecure Metadata"],
    mitreAtlas: ["Execution", "AI Agent Tool Abuse"],
    nistAiRmf: ["Map", "Manage"],
  },
  "format-injection": {
    owasp: ["AST04 Insecure Metadata", "LLM01 Prompt Injection"],
    mitreAtlas: ["AML.T0051 Prompt Injection"],
    nistAiRmf: ["Map", "Measure"],
  },
  "excessive-claims": {
    owasp: ["AST03 Over-Privileged Skills"],
    mitreAtlas: ["Privilege Escalation"],
    nistAiRmf: ["Govern", "Manage"],
  },
  "hidden-content": {
    owasp: ["AST01 Malicious Skills", "AST04 Insecure Metadata"],
    mitreAtlas: ["AML.T0054 Indirect Prompt Injection"],
    nistAiRmf: ["Map", "Measure"],
  },
  "hitl-bypass": {
    owasp: ["AST03 Over-Privileged Skills", "Human-in-the-Loop Bypass"],
    mitreAtlas: ["Privilege Escalation", "AI Agent Tool Abuse"],
    nistAiRmf: ["Govern", "Manage"],
  },
  "package-age": {
    owasp: ["AST02 Supply Chain Compromise", "LLM03 Supply Chain"],
    mitreAtlas: ["Supply Chain Compromise"],
    nistAiRmf: ["Map", "Govern", "Manage"],
  },
  "missing-provenance": {
    owasp: ["AST02 Supply Chain Compromise", "LLM03 Supply Chain"],
    mitreAtlas: ["Supply Chain Compromise"],
    nistAiRmf: ["Map", "Govern", "Manage"],
  },
};

export const RULES: RuleDefinition[] = [

  // ── Prompt injection ────────────────────────────────────────────────────
  // These patterns attempt to override the agent's existing instructions mid-skill.

  {
    id: "SS001",
    name: "ignore-previous-instructions",
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|guidelines?|rules?|prompts?)/i,
    severity: "danger",
    category: "prompt-injection",
    description: "Instructs the agent to ignore prior instructions.",
  },
  {
    id: "SS002",
    name: "disregard-prior-instructions",
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|guidelines?|rules?|prompts?)/i,
    severity: "danger",
    category: "prompt-injection",
    description: "Instructs the agent to disregard prior instructions.",
  },
  {
    id: "SS003",
    name: "forget-prior-context",
    pattern: /forget\s+(everything|all|what)\s+(you|you've|you were)/i,
    severity: "danger",
    category: "prompt-injection",
    description: "Instructs the agent to forget prior context.",
  },
  {
    id: "SS004",
    name: "redefine-system-prompt",
    pattern: /your\s+(new\s+)?system\s+prompt\s+is/i,
    severity: "danger",
    category: "prompt-injection",
    description: "Attempts to redefine the agent's system prompt.",
  },
  {
    id: "SS005",
    name: "override-agent-behavior",
    pattern: /override\s+(your\s+)?(instructions?|guidelines?|behavior|rules?)/i,
    severity: "danger",
    category: "prompt-injection",
    description: "Attempts to override agent behavior.",
  },
  {
    id: "SS006",
    name: "new-instructions-marker",
    pattern: /\[NEW\s+INST(RUCTION)?S?\]/i,
    severity: "danger",
    category: "prompt-injection",
    description: "Contains a new-instructions injection marker.",
  },

  // ── Identity hijacking ──────────────────────────────────────────────────
  // These patterns attempt to make the agent impersonate or become another entity.

  {
    id: "SS010",
    name: "redefine-agent-identity",
    // Exclude common legitimate phrases like "you are now able to", "you are now ready"
    pattern: /you\s+are\s+now\s+(?!(?:able|ready|going|required|allowed|expected|asked|set|configured|done)\b)/i,
    severity: "danger",
    category: "identity-hijack",
    description: "Attempts to redefine the agent's identity.",
  },
  {
    id: "SS011",
    name: "pretend-persona",
    pattern: /pretend\s+(you\s+are|to\s+be)\s+/i,
    severity: "danger",
    category: "identity-hijack",
    description: "Instructs the agent to pretend to be another entity.",
  },
  {
    id: "SS012",
    name: "act-as-persona",
    // "act as a hacker" triggers, but "act as a tool" / "act as a skill" / "act as an assistant" doesn't
    pattern: /act\s+as\s+(?:a|an)\s+(?!tool\b|skill\b|assistant\b|agent\b|helper\b|proxy\b)/i,
    severity: "caution",
    category: "identity-hijack",
    description: "Instructs the agent to act as a specific persona.",
  },
  {
    id: "SS013",
    name: "impersonation",
    pattern: /impersonate\s+/i,
    severity: "danger",
    category: "identity-hijack",
    description: "Explicitly instructs impersonation.",
  },
  {
    id: "SS014",
    name: "persistent-behavior-alteration",
    pattern: /from\s+now\s+on\s+you\s+(will|are|must)/i,
    severity: "caution",
    category: "identity-hijack",
    description: "Attempts to permanently alter agent behavior.",
  },

  // ── Jailbreak ───────────────────────────────────────────────────────────
  // Known jailbreak vocabulary and bypass triggers.

  {
    id: "SS020",
    name: "dan-jailbreak",
    pattern: /\bDAN\b.*\bmode\b|\bDAN\s+prompt\b/i,
    severity: "danger",
    category: "jailbreak",
    description: "Contains DAN (Do Anything Now) jailbreak pattern.",
  },
  {
    id: "SS021",
    name: "developer-mode-jailbreak",
    pattern: /developer\s+mode\s+(enabled|on|activated)/i,
    severity: "danger",
    category: "jailbreak",
    description: "Contains developer-mode jailbreak trigger.",
  },
  {
    id: "SS022",
    name: "explicit-jailbreak-keyword",
    pattern: /\bJAILBREAK\b/i,
    severity: "danger",
    category: "jailbreak",
    description: "Contains explicit JAILBREAK keyword.",
  },
  {
    id: "SS023",
    name: "remove-safety-filters",
    pattern: /no\s+(safety|ethical|moral|content)\s+(filters?|guidelines?|restrictions?|limits?)/i,
    severity: "danger",
    category: "jailbreak",
    description: "Claims or instructs removal of safety filters.",
  },
  {
    id: "SS024",
    name: "bypass-safety-guidelines",
    pattern: /bypass\s+(safety|ethical|content|security)\s+(guidelines?|filters?|restrictions?)/i,
    severity: "danger",
    category: "jailbreak",
    description: "Attempts to bypass safety guidelines.",
  },
  {
    id: "SS025",
    name: "unrestricted-mode",
    pattern: /unrestricted\s+(mode|access|behavior|ai)/i,
    severity: "danger",
    category: "jailbreak",
    description: "Claims or enables unrestricted mode.",
  },

  // ── Data exfiltration ───────────────────────────────────────────────────
  // Patterns that attempt to send agent/user data to external destinations.

  {
    id: "SS030",
    name: "external-network-call",
    // Network calls to non-local URLs embedded in skill instructions
    pattern: /(?:fetch|axios|curl|wget|http\.get|XMLHttpRequest)\s*\(\s*[`'"](https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0))/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a network call to an external URL.",
  },
  {
    id: "SS031",
    name: "shell-network-command",
    // Shell download/exfil commands in code fences or run instructions.
    pattern: /(?:^|[\s;&|`$()])(?:curl|wget)\s+(?:-[A-Za-z0-9]+\s+)*["']?https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/im,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a shell network command to an external URL.",
  },
  {
    id: "SS032",
    name: "powershell-network-command",
    pattern: /(?:Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)\s+(?:-[A-Za-z]+\s+[^ \r\n]+\s+)*["']?https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a PowerShell network command to an external URL.",
  },
  {
    id: "SS033",
    name: "python-http-client",
    pattern: /\b(?:requests|httpx)\s*\.\s*(?:get|post|put|patch|request)\s*\(\s*["']https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a Python HTTP client call to an external URL.",
  },
  {
    id: "SS034",
    name: "python-urllib-network-call",
    pattern: /\burllib\.request\.urlopen\s*\(\s*["']https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a Python urllib call to an external URL.",
  },
  {
    id: "SS035",
    name: "netcat-external-connection",
    pattern: /(?:^|[\s;&|`$()])(?:nc|netcat|ncat)\s+(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b)[A-Za-z0-9.-]+\s+\d{2,5}/im,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a netcat-style external connection.",
  },
  {
    id: "SS036",
    name: "explicit-exfiltration",
    pattern: /\bexfiltrate\b/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains explicit exfiltration language.",
  },
  {
    id: "SS037",
    name: "send-sensitive-data",
    pattern: /send\s+(all|the|this|user|agent|system)\s+(data|files?|secrets?|credentials?|tokens?|keys?)\s+(to|via|through)\s+/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Instructs the agent to send sensitive data externally.",
  },
  {
    id: "SS038",
    name: "external-webhook",
    // External webhook references are suspicious in skill files — legit skills declare integrations via config
    pattern: /webhook.*https?:\/\/(?!localhost|127\.0\.0\.1)/i,
    severity: "caution",
    category: "data-exfiltration",
    description: "References an external webhook URL.",
  },

  // ── Script injection ─────────────────────────────────────────────────────
  // Patterns that embed executable code directly into skill markdown.

  {
    id: "SS040",
    name: "script-tag",
    pattern: /<script[\s>]/i,
    severity: "danger",
    category: "script-injection",
    description: "Contains a <script> tag.",
  },
  {
    id: "SS041",
    name: "javascript-uri",
    pattern: /javascript\s*:/i,
    severity: "danger",
    category: "script-injection",
    description: "Contains a javascript: URI.",
  },
  {
    id: "SS042",
    name: "eval-call",
    pattern: /\beval\s*\(/i,
    severity: "danger",
    category: "script-injection",
    description: "Contains eval() call.",
  },
  {
    id: "SS043",
    name: "function-constructor",
    pattern: /new\s+Function\s*\(/i,
    severity: "danger",
    category: "script-injection",
    description: "Contains new Function() constructor (dynamic code execution).",
  },
  {
    id: "SS044",
    name: "python-runtime-import",
    pattern: /__import__\s*\(/i,
    severity: "danger",
    category: "script-injection",
    description: "Contains Python __import__() (runtime import injection).",
  },
  {
    id: "SS045",
    name: "process-execution-api",
    pattern: /\b(?:child_process|subprocess|os\.system|popen|execFile|spawn)\b/i,
    severity: "caution",
    category: "script-injection",
    description: "References process execution APIs.",
  },

  // ── LLM format injection ─────────────────────────────────────────────────
  // Raw LLM control tokens embedded in markdown — used to hijack chat formatting.

  {
    id: "SS050",
    name: "llm-control-token",
    pattern: /<\|(?:system|user|assistant|im_start|im_end|endoftext)\|>/i,
    severity: "danger",
    category: "format-injection",
    description: "Contains LLM control token (e.g. <|system|>, <|user|>).",
  },
  {
    id: "SS051",
    name: "llama-inst-token",
    pattern: /\[INST\]|\[\/INST\]/,
    severity: "danger",
    category: "format-injection",
    description: "Contains Llama-style [INST] instruction injection marker.",
  },
  {
    id: "SS052",
    name: "chat-role-marker",
    // These can be legit in documentation but are suspicious in operational skill files
    pattern: /###\s*(Human|Assistant|System)\s*:/,
    severity: "caution",
    category: "format-injection",
    description: "Contains raw chat-format role markers inside skill content.",
  },

  // ── Excessive privilege claims ───────────────────────────────────────────
  // False privilege assertions — legitimate skills never need to claim these.

  {
    id: "SS060",
    name: "unrestricted-access-claim",
    pattern: /you\s+have\s+(full|complete|unrestricted|unlimited)\s+(access|control|permission)/i,
    severity: "caution",
    category: "excessive-claims",
    description: "Claims the agent has unrestricted access/control.",
  },
  {
    id: "SS061",
    name: "admin-privileges-claim",
    pattern: /admin\s+(privileges?|rights?|access)\s+(granted|enabled|active)/i,
    severity: "caution",
    category: "excessive-claims",
    description: "Claims admin privileges are granted.",
  },
  {
    id: "SS062",
    name: "no-limitations-claim",
    pattern: /no\s+limitations?\s+(apply|exist|on)/i,
    severity: "caution",
    category: "excessive-claims",
    description: "Claims no limitations apply to this agent.",
  },
  {
    id: "SS063",
    name: "guardrails-disabled-claim",
    pattern: /all\s+(safety\s+)?guardrails?\s+(are\s+)?(off|disabled|removed|bypassed)/i,
    severity: "danger",
    category: "excessive-claims",
    description: "Claims all guardrails have been removed.",
  },

  // -- HITL bypass / self-approval -------------------------------------------------
  // Agent skills should never instruct the agent to approve, bypass, or forge
  // user consent for risky operations.

  {
    id: "SS070",
    name: "self-approval",
    pattern: /(?:auto|self)[-\s]?approve\s+(?:all\s+)?(?:actions?|tool\s+calls?|requests?|changes?|patches?)/i,
    severity: "danger",
    category: "hitl-bypass",
    description: "Attempts to self-approve agent actions without human review.",
    owasp: ["Human-in-the-Loop Bypass", "Excessive Agency"],
    nistAiRmf: ["Govern"],
  },
  {
    id: "SS071",
    name: "approval-bypass",
    pattern: /(?:do\s+not|don't|never)\s+(?:ask|request|wait\s+for)\s+(?:user|human|operator)\s+(?:approval|confirmation|permission|consent)/i,
    severity: "danger",
    category: "hitl-bypass",
    description: "Instructs the agent to bypass user approval.",
    owasp: ["Human-in-the-Loop Bypass", "Excessive Agency"],
    nistAiRmf: ["Govern"],
  },
  {
    id: "SS072",
    name: "implicit-approval",
    pattern: /(?:assume|treat)\s+(?:approval|confirmation|permission|consent)\s+(?:is|as)\s+(?:granted|given|implicit|pre[-\s]?approved)/i,
    severity: "danger",
    category: "hitl-bypass",
    description: "Treats user approval as implicitly granted.",
    owasp: ["Human-in-the-Loop Bypass"],
    nistAiRmf: ["Govern"],
  },

  // -- Hidden payloads / encoded content ------------------------------------------
  // Long encoded blobs in skills are not always malicious, but they deserve a
  // higher-friction review because they hide operational content from humans.

  {
    id: "SS080",
    name: "encoded-payload",
    pattern: /\b(?:base64|atob|fromBase64|Buffer\.from)\b[\s\S]{0,120}\b[A-Za-z0-9+/]{80,}={0,2}\b/i,
    severity: "caution",
    category: "hidden-content",
    description: "Contains a large base64-like payload or decoder reference.",
    owasp: ["Agentic Instruction and Tool Manipulation"],
  },

];
