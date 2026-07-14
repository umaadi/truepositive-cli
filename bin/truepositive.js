#!/usr/bin/env node
/**
 * truepositive — is that CVE real, or scanner noise?
 *
 * Reads the public, read-only API at truepositive.app and prints the signals that
 * actually decide whether a finding matters: CISA KEV, EPSS, CVSS, and the field
 * verdict from practitioners who triaged it.
 *
 * Honesty rule this CLI must never break: a verdict from real practitioners (the
 * "field verdict") and TruePositive's own curated baseline are DIFFERENT things and
 * are always rendered as such. We never print a curated baseline as if the field
 * said it.
 *
 * No dependencies. Node 18+ (global fetch).
 */

const API = process.env.TRUEPOSITIVE_API || "https://www.truepositive.app";
const VERSION = "0.1.0";

const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;

// ---- tiny ANSI helper (no deps) --------------------------------------------
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code) => (s) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = paint("1");
const dim = paint("2");
const red = paint("31");
const green = paint("32");
const yellow = paint("33");
const blue = paint("34");
const cyan = paint("36");
const gray = paint("90");

// Colour by how much the verdict should worry you.
const VERDICT_COLOR = {
  real_exploitable: red,
  real_conditional: yellow,
  real_theoretical: yellow,
  not_applicable: blue,
  mitigated: cyan,
  false_positive: gray,
  cannot_reproduce: gray,
};

const HELP = `
${bold("truepositive")} — is that CVE real, or scanner noise?

${bold("Usage")}
  npx truepositive <CVE-ID> [CVE-ID...] [options]

${bold("Options")}
  --json          Print the raw API response instead of the report
  --fail-on-kev   Exit 2 if any CVE is in the CISA KEV catalog (useful in CI)
  -h, --help      Show this help
  -v, --version   Show version

${bold("Examples")}
  npx truepositive CVE-2021-44228
  npx truepositive CVE-2021-44228 CVE-2023-4966 --json
  npx truepositive CVE-2023-34362 --fail-on-kev

${bold("Exit codes")}
  0  ok
  1  bad input, CVE not found, or network error
  2  --fail-on-kev matched

Data: ${API}  ·  Field verdicts are contributed by security practitioners.
`;

function pct(n) {
  if (n == null) return null;
  const p = n * 100;
  return p >= 10 ? `${p.toFixed(0)}%` : `${p.toFixed(1)}%`;
}

function row(label, value) {
  return `  ${gray(label.padEnd(18))}${value}`;
}

function render(d) {
  const lines = [];
  lines.push("");
  lines.push(`  ${bold(d.cveId)}  ${dim(d.url)}`);
  lines.push("");

  // --- signals -------------------------------------------------------------
  if (d.cvss != null) {
    lines.push(row("CVSS", `${bold(String(d.cvss))} ${gray(d.cvssSeverity ?? "")}`));
  }
  lines.push(
    row(
      "CISA KEV",
      d.kev
        ? `${red("yes")} ${gray("confirmed exploited in the wild")}`
        : `${gray("no")}`,
    ),
  );
  if (d.epss != null) {
    lines.push(row("EPSS", `${pct(d.epss)} ${gray("chance of exploitation in 30 days")}`));
  }
  lines.push("");

  // --- field verdict (real practitioners ONLY) -----------------------------
  const c = d.community ?? {};
  if (c.sampleSize > 0 && c.topVerdict) {
    const color = VERDICT_COLOR[c.topVerdict] ?? ((s) => s);
    const n = c.sampleSize;
    lines.push(row("Field verdict", `${color(bold(c.topVerdictLabel))} ${gray(`· ${n} verdict${n === 1 ? "" : "s"}`)}`));
    const sev = c.practicalSeverity?.top;
    if (sev) lines.push(row("Practical severity", sev));
  } else {
    lines.push(row("Field verdict", gray("none yet — be the first to report one")));
  }

  // --- curated baseline (ours — NEVER shown as a field verdict) ------------
  if (d.editorial?.verdict) {
    const color = VERDICT_COLOR[d.editorial.verdict] ?? ((s) => s);
    lines.push("");
    lines.push(row("Curated baseline", `${color(d.editorial.verdictLabel)}${d.editorial.practicalSeverity ? gray(` · ${d.editorial.practicalSeverity}`) : ""}`));
    lines.push(`  ${gray("                  TruePositive curated baseline, not a community verdict")}`);
  }

  // --- the money signal ----------------------------------------------------
  if (d.divergesFromCvss) {
    lines.push("");
    lines.push(`  ${yellow("⚠ Diverges from CVSS")} ${gray("— high on paper, but the field says it is not a real risk here.")}`);
  }

  lines.push("");
  return lines.join("\n");
}

async function lookup(cveId) {
  const res = await fetch(`${API}/api/cve/${encodeURIComponent(cveId)}/verdict`, {
    headers: {
      Accept: "application/json",
      "User-Agent": `truepositive-cli/${VERSION}`,
      // Don't leave a keep-alive socket open — it delays process exit for a CLI.
      Connection: "close",
    },
  });
  if (res.status === 404) {
    const e = new Error(`${cveId} is not in TruePositive yet.`);
    e.soft = true;
    throw e;
  }
  if (!res.ok) throw new Error(`API returned ${res.status} for ${cveId}`);
  return res.json();
}

// Set the exit code and let Node drain naturally. Calling process.exit() here trips
// a libuv assertion on Windows when stdout writes are still in flight.
async function main() {
  const argv = process.argv.slice(2);

  if (!argv.length || argv.includes("-h") || argv.includes("--help")) {
    console.log(HELP);
    process.exitCode = argv.length ? 0 : 1;
    return;
  }
  if (argv.includes("-v") || argv.includes("--version")) {
    console.log(VERSION);
    return;
  }

  const json = argv.includes("--json");
  const failOnKev = argv.includes("--fail-on-kev");
  const ids = argv.filter((a) => !a.startsWith("-"));

  if (!ids.length) {
    console.error(red("error:") + " no CVE id given. Try: npx truepositive CVE-2021-44228");
    process.exitCode = 1;
    return;
  }

  const bad = ids.filter((id) => !CVE_RE.test(id));
  if (bad.length) {
    console.error(red("error:") + ` not a valid CVE id: ${bad.join(", ")}`);
    process.exitCode = 1;
    return;
  }

  const results = [];
  let failed = false;
  let anyKev = false;

  for (const raw of ids) {
    const id = raw.toUpperCase();
    try {
      const data = await lookup(id);
      results.push(data);
      if (data.kev) anyKev = true;
      if (!json) console.log(render(data));
    } catch (err) {
      failed = true;
      if (json) results.push({ cveId: id, error: err.message });
      else console.error(`\n  ${bold(id)}  ${err.soft ? gray(err.message) : red(err.message)}\n`);
    }
  }

  if (json) console.log(JSON.stringify(results.length === 1 ? results[0] : results, null, 2));

  if (failOnKev && anyKev) {
    if (!json) console.error(red("x ") + "at least one CVE is in the CISA KEV catalog (confirmed exploited).");
    process.exitCode = 2;
    return;
  }
  process.exitCode = failed ? 1 : 0;
}

main().catch((err) => {
  console.error(red("error:") + " " + (err?.message ?? err));
  process.exitCode = 1;
});
