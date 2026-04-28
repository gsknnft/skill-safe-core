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

import type { GovernanceMapping, RuleDefinition } from "./types.js";

// Shared governance mapping constants to avoid repetition across rules.
const OWASP_SENSITIVE_DISCLOSURE: GovernanceMapping = {
  framework: "owasp-llm", id: "LLM02", label: "Sensitive Information Disclosure",
  url: "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
  sourceVersion: "2025", confidence: "direct",
};
const OWASP_SUPPLY_CHAIN: GovernanceMapping = {
  framework: "owasp-llm", id: "LLM03", label: "Supply Chain",
  url: "https://genai.owasp.org/llmrisk/llm03-supply-chain/",
  sourceVersion: "2025", confidence: "direct",
};
const OWASP_EXCESSIVE_AGENCY: GovernanceMapping = {
  framework: "owasp-agentic", id: "AST03", label: "Over-Privileged Agent Skills",
  url: "https://owasp.org/www-project-agentic-ai-threat-landscape/",
  sourceVersion: "2025", confidence: "direct",
};
const OWASP_HITL_BYPASS: GovernanceMapping = {
  framework: "owasp-agentic", id: "AST06", label: "Human-in-the-Loop Bypass",
  url: "https://owasp.org/www-project-agentic-ai-threat-landscape/",
  sourceVersion: "2025", confidence: "direct",
};
const OWASP_PROMPT_INJECTION: GovernanceMapping = {
  framework: "owasp-llm", id: "LLM01", label: "Prompt Injection",
  url: "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
  sourceVersion: "2025", confidence: "direct",
};
const OWASP_TOOL_MANIPULATION: GovernanceMapping = {
  framework: "owasp-agentic", id: "AST01", label: "Malicious Skill / Tool Manipulation",
  url: "https://owasp.org/www-project-agentic-ai-threat-landscape/",
  sourceVersion: "2025", confidence: "related",
};
const MITRE_EXFIL: GovernanceMapping = {
  framework: "mitre-atlas", id: "AML.T0040", label: "Exfiltration via ML Inference API",
  url: "https://atlas.mitre.org/techniques/AML.T0040", confidence: "direct",
};
const MITRE_SUPPLY_CHAIN: GovernanceMapping = {
  framework: "mitre-atlas", id: "AML.T0010", label: "ML Supply Chain Compromise",
  url: "https://atlas.mitre.org/techniques/AML.T0010", confidence: "direct",
};
const MITRE_PERSISTENCE: GovernanceMapping = {
  framework: "mitre-atlas", id: "AML.T0044", label: "Full ML Model Access",
  url: "https://atlas.mitre.org/techniques/AML.T0044", confidence: "related",
};
const MITRE_PROMPT_INJECTION: GovernanceMapping = {
  framework: "mitre-atlas", id: "AML.T0051", label: "LLM Prompt Injection",
  url: "https://atlas.mitre.org/techniques/AML.T0051", confidence: "direct",
};
const NIST_MAP: GovernanceMapping = {
  framework: "nist-ai-rmf", id: "MAP", label: "Map", confidence: "direct",
};
const NIST_GOVERN: GovernanceMapping = {
  framework: "nist-ai-rmf", id: "GOVERN", label: "Govern", confidence: "direct",
};

export const RULES: RuleDefinition[] = [
  // ── Prompt injection ────────────────────────────────────────────────────
  // These patterns attempt to override the agent's existing instructions mid-skill.

  {
    id: "SS001",
    name: "ignore-previous-instructions",
    pattern:
      /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|guidelines?|rules?|prompts?)/i,
    severity: "danger",
    category: "prompt-injection",
    description: "Instructs the agent to ignore prior instructions.",
  },
  {
    id: "SS002",
    name: "disregard-prior-instructions",
    pattern:
      /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|guidelines?|rules?|prompts?)/i,
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
    pattern:
      /override\s+(your\s+)?(instructions?|guidelines?|behavior|rules?)/i,
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
    pattern:
      /you\s+are\s+now\s+(?!(?:able|ready|going|required|allowed|expected|asked|set|configured|done)\b)/i,
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
    pattern:
      /act\s+as\s+(?:a|an)\s+(?!tool\b|skill\b|assistant\b|agent\b|helper\b|proxy\b)/i,
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
    pattern:
      /no\s+(safety|ethical|moral|content)\s+(filters?|guidelines?|restrictions?|limits?)/i,
    severity: "danger",
    category: "jailbreak",
    description: "Claims or instructs removal of safety filters.",
  },
  {
    id: "SS024",
    name: "bypass-safety-guidelines",
    pattern:
      /bypass\s+(safety|ethical|content|security)\s+(guidelines?|filters?|restrictions?)/i,
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
    pattern:
      /(?:fetch|axios|curl|wget|http\.get|XMLHttpRequest)\s*\(\s*[`'"](https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0))/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a network call to an external URL.",
  },
  {
    id: "SS031",
    name: "shell-network-command",
    // Shell download/exfil commands in code fences or run instructions.
    pattern:
      /(?:^|[\s;&|`$()])(?:curl|wget)\s+(?:-[A-Za-z0-9]+\s+)*["']?https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/im,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a shell network command to an external URL.",
  },
  {
    id: "SS032",
    name: "powershell-network-command",
    pattern:
      /(?:Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)\s+(?:-[A-Za-z]+\s+[^ \r\n]+\s+)*["']?https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a PowerShell network command to an external URL.",
  },
  {
    id: "SS033",
    name: "python-http-client",
    pattern:
      /\b(?:requests|httpx)\s*\.\s*(?:get|post|put|patch|request)\s*\(\s*["']https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a Python HTTP client call to an external URL.",
  },
  {
    id: "SS034",
    name: "python-urllib-network-call",
    pattern:
      /\burllib\.request\.urlopen\s*\(\s*["']https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Contains a Python urllib call to an external URL.",
  },
  {
    id: "SS035",
    name: "netcat-external-connection",
    pattern:
      /(?:^|[\s;&|`$()])(?:nc|netcat|ncat)\s+(?!localhost\b|127\.0\.0\.1\b|0\.0\.0\.0\b)[A-Za-z0-9.-]+\s+\d{2,5}/im,
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
    pattern:
      /send\s+(all|the|this|user|agent|system)\s+(data|files?|secrets?|credentials?|tokens?|keys?)\s+(to|via|through)\s+/i,
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
    description:
      "Contains new Function() constructor (dynamic code execution).",
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
    pattern:
      /\b(?:child_process|subprocess|os\.system|popen|execFile|spawn)\b/i,
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
    pattern:
      /you\s+have\s+(full|complete|unrestricted|unlimited)\s+(access|control|permission)/i,
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
    pattern:
      /all\s+(safety\s+)?guardrails?\s+(are\s+)?(off|disabled|removed|bypassed)/i,
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
    pattern:
      /(?:auto|self)[-\s]?approve\s+(?:all\s+)?(?:actions?|tool\s+calls?|requests?|changes?|patches?)/i,
    severity: "danger",
    category: "hitl-bypass",
    description: "Attempts to self-approve agent actions without human review.",
    governance: [OWASP_HITL_BYPASS, OWASP_EXCESSIVE_AGENCY, NIST_GOVERN],
  },
  {
    id: "SS071",
    name: "approval-bypass",
    pattern:
      /(?:do\s+not|don't|never)\s+(?:ask|request|wait\s+for)\s+(?:user|human|operator)\s+(?:approval|confirmation|permission|consent)/i,
    severity: "danger",
    category: "hitl-bypass",
    description: "Instructs the agent to bypass user approval.",
    governance: [OWASP_HITL_BYPASS, OWASP_EXCESSIVE_AGENCY, NIST_GOVERN],
  },
  {
    id: "SS072",
    name: "implicit-approval",
    pattern:
      /(?:assume|treat)\s+(?:approval|confirmation|permission|consent)\s+(?:is|as)\s+(?:granted|given|implicit|pre[-\s]?approved)/i,
    severity: "danger",
    category: "hitl-bypass",
    description: "Treats user approval as implicitly granted.",
    governance: [OWASP_HITL_BYPASS, NIST_GOVERN],
  },

  // -- Hidden payloads / encoded content ------------------------------------------
  // Long encoded blobs in skills are not always malicious, but they deserve a
  // higher-friction review because they hide operational content from humans.

  {
    id: "SS080",
    name: "encoded-payload",
    pattern:
      /\b(?:base64|atob|fromBase64|Buffer\.from)\b[\s\S]{0,120}\b[A-Za-z0-9+/]{80,}={0,2}\b/i,
    severity: "caution",
    category: "hidden-content",
    description: "Contains a large base64-like payload or decoder reference.",
    governance: [OWASP_TOOL_MANIPULATION],
  },

  // -- Credential and secrets access -----------------------------------------------
  // Skills that read private keys, tokens, or credential stores are extremely
  // high risk; they can silently harvest authentication material.

  {
    id: "SS100",
    name: "ssh-key-read",
    pattern:
      /(?:read|cat|open|load|get)\s+(?:.*?\/)?\.ssh\/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Reads an SSH private key or authorized_keys file.",
    governance: [
      {
        framework: "owasp-agentic",
        id: "LLM02",
        label: "Sensitive Information Disclosure",
        url: "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/",
        sourceVersion: "2025",
        confidence: "direct",
      },
      {
        framework: "mitre-atlas",
        id: "AML.T0040",
        label: "Exfiltration via ML Inference API",
        url: "https://atlas.mitre.org/techniques/AML.T0040",
        confidence: "direct",
      },
      {
        framework: "nist-ai-rmf",
        id: "MAP",
        label: "Map",
        confidence: "direct",
      },
    ],
  },
  {
    id: "SS101",
    name: "env-file-read",
    // Match: require('.env'), open('.env.production'), cat .env, fs.readFile('.env.local')
    pattern:
      /(?:read|cat|open|load|require|import|fs\.readFile)\s*[\s(]?\s*['"`]?(?:\.\/|\/)?\.env(?:\.(?:local|production|staging|test|development))?['"`]?/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Reads a .env or environment secrets file.",
    governance: [OWASP_SENSITIVE_DISCLOSURE, MITRE_EXFIL, NIST_MAP],
  },
  {
    id: "SS102",
    name: "aws-credentials-read",
    pattern: /(?:read|cat|open|load)\s+(?:.*?\/)?\.aws\/credentials/i,
    severity: "danger",
    category: "data-exfiltration",
    description: "Reads AWS credential files.",
    governance: [OWASP_SENSITIVE_DISCLOSURE, MITRE_EXFIL, NIST_MAP],
  },
  {
    id: "SS103",
    name: "token-env-access",
    // Matches: process.env.GITHUB_TOKEN, process.env['OPENAI_API_KEY'], os.environ['SECRET']
    pattern:
      /(?:process\.env|os\.environ|getenv|System\.getenv)\s*[\[.(][\s'"` ]*[A-Z_]{4,}_(?:TOKEN|KEY|SECRET|PASSWORD|CREDENTIAL|API_KEY)/i,
    severity: "caution",
    category: "data-exfiltration",
    description: "Accesses an environment variable that likely holds a secret or API key.",
    governance: [OWASP_SENSITIVE_DISCLOSURE, NIST_MAP],
  },

  // -- Remote code execution -------------------------------------------------------
  // Patterns that pipe remote content directly into a shell interpreter bypass
  // supply-chain controls entirely.

  {
    id: "SS110",
    name: "curl-pipe-shell",
    pattern: /curl\s+[^\n|&;]{0,200}\|\s*(?:bash|sh|zsh|fish|dash|ash|ksh)/i,
    severity: "danger",
    category: "script-injection",
    description: "Pipes a remote URL directly into a shell — classic supply-chain attack vector.",
    governance: [OWASP_SUPPLY_CHAIN, MITRE_SUPPLY_CHAIN, NIST_MAP],
  },
  {
    id: "SS111",
    name: "wget-pipe-shell",
    pattern: /wget\s+[^\n|&;]{0,200}\|\s*(?:bash|sh|zsh|fish|dash|ash|ksh)/i,
    severity: "danger",
    category: "script-injection",
    description: "Pipes a remote URL directly into a shell.",
    governance: [OWASP_SUPPLY_CHAIN, MITRE_SUPPLY_CHAIN, NIST_MAP],
  },
  {
    id: "SS112",
    name: "powershell-iex-download",
    // IEX / Invoke-Expression with a download — common PowerShell dropper pattern.
    pattern:
      /(?:iex|Invoke-Expression)\s*(?:\(|\s).*?(?:DownloadString|WebClient|Invoke-WebRequest|curl|wget)/i,
    severity: "danger",
    category: "script-injection",
    description: "PowerShell Invoke-Expression with a remote download — dropper pattern.",
    governance: [OWASP_SUPPLY_CHAIN, MITRE_SUPPLY_CHAIN, NIST_MAP],
  },
  {
    id: "SS113",
    name: "remote-prompt-load",
    // Agents that load additional instructions from a remote URL at runtime are
    // susceptible to indirect prompt injection via the remote resource.
    pattern:
      /(?:fetch|axios|http\.get|got|request)\s*\(\s*(?:(?:['"`]https?:\/\/[^'"` )]{10,}['"`])|(?:[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?))\s*\)[\s\S]{0,240}(?:system\s+prompt|instruction|directive|eval|exec)/i,
    severity: "danger",
    category: "prompt-injection",
    description: "Loads remote content and passes it as instructions — indirect prompt injection risk.",
    governance: [OWASP_PROMPT_INJECTION, MITRE_PROMPT_INJECTION, NIST_MAP],
  },

  // -- Destructive filesystem operations -------------------------------------------

  {
    id: "SS120",
    name: "recursive-delete",
    pattern: /rm\s+(?:-[rfRF]{1,4}\s+|--recursive\s+|--force\s+){1,3}[/~.]/i,
    severity: "danger",
    category: "script-injection",
    description: "Recursive force-delete from root, home, or current directory.",
    governance: [OWASP_EXCESSIVE_AGENCY, MITRE_PERSISTENCE, NIST_MAP],
  },
  {
    id: "SS121",
    name: "format-disk",
    pattern: /(?:mkfs|format\s+[a-z]:?|diskpart|dd\s+if=\/dev\/zero)/i,
    severity: "danger",
    category: "script-injection",
    description: "Disk format or zero-fill command — highly destructive.",
    governance: [OWASP_EXCESSIVE_AGENCY, MITRE_PERSISTENCE, NIST_MAP],
  },

  // -- Shell profile and persistence -----------------------------------------------
  // Skills that write to shell profiles can persist malicious instructions across
  // sessions long after the skill is removed.

  {
    id: "SS130",
    name: "shell-profile-write",
    pattern:
      /(?:echo|printf|tee|>>)\s+.*(?:\.bash_profile|\.bashrc|\.zshrc|\.profile|\.zprofile|\.bash_login|\/etc\/profile|\/etc\/environment)/i,
    severity: "danger",
    category: "script-injection",
    description: "Writes to a shell profile or startup script — persistence mechanism.",
    governance: [OWASP_EXCESSIVE_AGENCY, MITRE_PERSISTENCE, NIST_GOVERN],
  },
  {
    id: "SS131",
    name: "cron-write",
    pattern: /(?:crontab\s+-[el]|echo\s+.*\|\s*crontab|\/etc\/cron)/i,
    severity: "danger",
    category: "script-injection",
    description: "Modifies cron jobs — can establish scheduled persistence.",
    governance: [OWASP_EXCESSIVE_AGENCY, MITRE_PERSISTENCE, NIST_GOVERN],
  },

  // -- Clipboard exfiltration ------------------------------------------------------

  {
    id: "SS140",
    name: "clipboard-exfiltration",
    pattern:
      /(?:pbcopy|xclip\s+-selection\s+clipboard|xdotool\s+type|Set-Clipboard|Get-Clipboard)\s*[|<]/i,
    severity: "caution",
    category: "data-exfiltration",
    description: "Exfiltrates content via the system clipboard.",
    governance: [OWASP_SENSITIVE_DISCLOSURE, NIST_MAP],
  },
];
