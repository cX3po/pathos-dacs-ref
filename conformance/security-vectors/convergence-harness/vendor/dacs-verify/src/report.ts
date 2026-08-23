// Implementation-report emitter. CONTRIBUTING.md asks for the highest-signal
// format: a §section, the artifact/file path, and an alternate interpretation
// or proposed fix. The verifier emits Findings in exactly that shape when it
// hits a spec ambiguity, inconsistency, or substrate mismatch — so "I read the
// spec" becomes "I implemented it and here is precisely where it breaks."

export type FindingBucket = "spec-defect" | "composition" | "substrate-grounding" | "editorial";

export interface Finding {
  id: string; // e.g. "DACS-VERIFY-0001"
  section: string; // e.g. "§6.3.1"
  filePath: string; // e.g. "spec/SPECIFICATION.md"
  bucket: FindingBucket;
  title: string;
  observed: string; // what the implementation found
  alternate: string; // alternate interpretation / proposed fix
  confidence: "high" | "medium" | "low";
}

export function formatFinding(f: Finding): string {
  return [
    `### ${f.id} — ${f.title}`,
    ``,
    `- **Section:** ${f.section}`,
    `- **File:** \`${f.filePath}\``,
    `- **Bucket:** ${f.bucket} · **Confidence:** ${f.confidence}`,
    `- **Observed (from implementing it):** ${f.observed}`,
    `- **Alternate interpretation / proposed fix:** ${f.alternate}`,
    ``,
  ].join("\n");
}

export function formatReport(findings: Finding[]): string {
  return findings.map(formatFinding).join("\n");
}
