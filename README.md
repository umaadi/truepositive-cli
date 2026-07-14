# truepositive-cli

**Is that CVE real, or just scanner noise?** Check it from your terminal.

A tiny, zero-dependency CLI for [TruePositive](https://www.truepositive.app) — community
ground truth on CVEs. It pulls the signals that actually decide whether a finding matters
(CISA KEV, EPSS, CVSS) plus the **field verdict** from practitioners who triaged it.

```bash
npx truepositive CVE-2021-44228
```

```
  CVE-2021-44228  https://www.truepositive.app/cve/CVE-2021-44228

  CVSS              10 critical
  CISA KEV          yes confirmed exploited in the wild
  EPSS              100% chance of exploitation in 30 days

  Field verdict     Real & exploitable · 4 verdicts
  Practical severity critical
```

## Why

Your scanner flagged 400 CVEs. Most of them don't matter. CVSS tells you how bad a bug is
*in theory* — it can't tell you whether it's exploitable **in your environment**, or whether
half the industry already wrote it off as noise.

Here's the case that makes the point:

```bash
npx truepositive CVE-2016-1000027
```

```
  CVE-2016-1000027  https://www.truepositive.app/cve/CVE-2016-1000027

  CVSS              9.8 critical
  CISA KEV          no
  EPSS              32% chance of exploitation in 30 days

  Curated baseline  False positive / noise
                    TruePositive curated baseline, not a community verdict
```

**CVSS 9.8 critical** — and it's the textbook dependency-scanner false positive. It's only
real if your app actually exposes Spring's HTTP Invoker remoting, which almost nobody does.
Every Spring app gets flagged anyway.

That gap is the whole point.

## Install

Nothing to install — just use `npx`:

```bash
npx truepositive CVE-2021-44228
```

Or install it globally:

```bash
npm install -g truepositive-cli
truepositive CVE-2021-44228
```

Requires Node 18+.

## Usage

```
npx truepositive <CVE-ID> [CVE-ID...] [options]
```

| Option | What it does |
|---|---|
| `--json` | Print the raw API response instead of the report |
| `--fail-on-kev` | Exit `2` if any CVE is in the CISA KEV catalog — useful in CI |
| `-h, --help` | Show help |
| `-v, --version` | Show version |

**Exit codes:** `0` ok · `1` bad input / not found / network error · `2` `--fail-on-kev` matched

### Check several at once

```bash
npx truepositive CVE-2021-44228 CVE-2023-4966 CVE-2022-22965
```

### Pipe it into something else

```bash
npx truepositive CVE-2021-44228 --json | jq '.community.topVerdict'
```

### Gate a build on known-exploited CVEs

```yaml
# .github/workflows/security.yml
- name: Block known-exploited CVEs
  run: npx truepositive CVE-2023-34362 --fail-on-kev
```

## Field verdict vs curated baseline

These are **two different things** and this CLI always keeps them apart:

- **Field verdict** — what real security practitioners reported after triaging the CVE in
  their own environment. This is the ground truth you came for.
- **Curated baseline** — TruePositive's own editorial annotation, grounded in NVD, CISA KEV
  and EPSS. It's a starting point, **not** a community verdict, and it is always labelled as
  such.

We will never print a curated baseline as if the field said it. If nobody has weighed in yet,
it says so:

```
  Field verdict     none yet — be the first to report one
```

[Add yours →](https://www.truepositive.app)

## Working from a full scanner report?

De-noise it first with **[Denoizr](https://denoizr.io)** — drop in a Nessus, Burp, Trivy,
Snyk or SARIF report and it merges, de-dupes and groups the findings into a conservative
first pass. It's free, and it runs entirely in your browser, so the report never leaves your
machine. Then bring whatever survives here for the field verdict.

*(Denoizr is built by the same maker as TruePositive.)*

## Badge

Drop the community verdict for a CVE straight into your README or advisory:

```markdown
![TruePositive](https://www.truepositive.app/cve/CVE-2021-44228/badge.svg)
```

The badge label tells you where the verdict came from: `truepositive · field` for a
practitioner verdict, `truepositive · curated` for our editorial baseline.

## API

The CLI is a thin wrapper over a public, read-only, CORS-open endpoint. Use it directly:

```bash
curl https://www.truepositive.app/api/cve/CVE-2021-44228/verdict
```

Full docs: [truepositive.app/developers](https://www.truepositive.app/developers)

## License

MIT

---

Built by [Umaadi](https://github.com/umaadi) · [truepositive.app](https://www.truepositive.app) · [denoizr.io](https://denoizr.io)
