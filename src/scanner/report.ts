import chalk from "chalk";
import { ScanResult, Severity } from "../types.js";

const COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue,
  info: chalk.gray,
};

export function renderJson(r: ScanResult): string {
  return JSON.stringify(r, null, 2);
}

/** SARIF 2.1.0 — ingestible by GitHub code scanning and other SARIF viewers. */
export function renderSarif(r: ScanResult): string {
  const level = (s: Severity): "error" | "warning" | "note" =>
    s === "critical" || s === "high" ? "error" : s === "medium" ? "warning" : "note";
  const rules = [...new Set(r.findings.map((f) => f.ruleId))].map((id) => ({ id }));
  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "malskanner",
              version: "0.1.0",
              informationUri: "https://github.com/octolabo/malskanner",
              rules,
            },
          },
          results: r.findings.map((f) => ({
            ruleId: f.ruleId,
            level: level(f.severity),
            message: { text: `${f.title}: ${f.evidence}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file },
                  region: { startLine: f.line, startColumn: f.column },
                },
              },
            ],
          })),
        },
      ],
    },
    null,
    2,
  );
}

export function renderHuman(r: ScanResult): string {
  const badge =
    r.verdict === "REFUSE"
      ? chalk.bgRed.white.bold(" REFUSE ")
      : r.verdict === "WARN"
        ? chalk.bgYellow.black.bold(" WARN ")
        : chalk.bgGreen.black.bold(" OK ");

  const lines: string[] = [
    "",
    `  ${chalk.bold("malskanner")}  ${badge}  risk ${r.score}/100   ${r.filesScanned} file(s) scanned`,
    "",
  ];

  if (r.findings.length === 0) {
    lines.push(chalk.green("  ✔ No hidden-payload findings."), "");
    return lines.join("\n");
  }

  for (const f of r.findings) {
    lines.push(
      `  ${COLOR[f.severity](` ${f.severity.toUpperCase()} `)} ${chalk.bold(f.title)}`,
      `    ${chalk.dim(`${f.file}:${f.line}:${f.column}`)}  ${chalk.dim(`[${f.ruleId}]`)}`,
      `    ${chalk.cyan("evidence")}  ${f.evidence}`,
      `    ${chalk.dim("why")}       ${f.why}`,
      `    ${chalk.dim("fix")}       ${f.remediation}`,
      "",
    );
  }

  const code = r.verdict === "REFUSE" ? 2 : r.verdict === "WARN" ? 1 : 0;
  lines.push(`  ${chalk.bold(String(r.findings.length))} finding(s) · exit code ${code}`, "");
  return lines.join("\n");
}
