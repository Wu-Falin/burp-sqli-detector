# SQLi Auto-Detection Extension for Burp Suite

A Burp Suite extension (Montoya API) that **automates the detection** of likely
SQL injection points during an authorized testing session. It flags suspicious
parameters with a confidence score so you don't have to hand-test every
parameter — then you confirm and exploit manually.

> **Detection only.** This tool stops at *"this parameter looks injectable."* It
> does not enumerate databases, tables, or columns, and it never extracts or
> modifies data. Turning a finding into proof (UNION dumps, table enumeration,
> etc.) is a deliberate manual step you perform yourself in Repeater.

---

## What it does

For every parameter in **in-scope** traffic that Burp actively audits, the
extension runs up to three lightweight checks and combines them into a single
High / Medium / Low confidence score. Findings are reported as **native Burp
Scanner issues** (Target → Issues) and collected in a dedicated **SQLi Detector**
tab for quick review.

Each finding records: the parameter name, confidence, the payload used, an
evidence snippet (error text / length diff / timing delta), and the OWASP
mapping **WSTG-INPVAL-05 — Testing for SQL Injection**.

### Detection modules

| Module | Technique | Signal → confidence |
| --- | --- | --- |
| **Error-based** | Injects the probe characters `'` `"` `\` `';--` and looks for known DB error signatures (MySQL, MSSQL, PostgreSQL, Oracle, SQLite). | Match = **High** |
| **Boolean-based blind** | Sends a TRUE pair (`' AND 1=1-- `) and a FALSE pair (`' AND 1=2-- `) and compares status code + body length. TRUE ≈ baseline while FALSE diverges = signal. | **Medium–High** |
| **Time-based blind** | Sends DB-specific delay payloads (MySQL `SLEEP(5)`, MSSQL `WAITFOR DELAY '0:0:5'`, PostgreSQL `pg_sleep(5)`), measures response time, and **repeats to confirm** before flagging. | **Medium–High**, labelled *"timing-based, verify manually"* |

The error-based signal is weighted highest; timing is treated as the least
reliable and always calls for manual verification.

---

## The detection-only design decision (and why)

This is the core design choice, enforced in code — not just described here:

- **Scope-gated.** Every check begins with `api.scope().isInScope(url)`. If the
  host isn't in Burp's configured **Target Scope**, nothing fires. See
  `SqliScanCheck.activeAudit()`.
- **It stops at detection.** No module attempts to enumerate schema or read/write
  data. The scan check builds an issue and a summary row and returns — there is
  no "dump" path anywhere in the codebase, and (per the project brief) an
  auto-dump feature is intentionally out of scope, not even as a toggle.
- **Curated, conservative payloads.** A handful of high-signal probes per module
  rather than a fuzzing dictionary — this is a detection aid, not a parameter
  hammer.

**Why draw the line here?** Detection is the safe, high-value part to automate:
it saves the tester from manually poking every parameter while keeping a human
in the loop for anything that touches real data. Automated *exploitation* against
a live target is where the risk of accidental data modification, outages, or
scope violations lives — so that stays a deliberate, manual step. Knowing *where*
to stop automating is the point.

---

## Safety defaults

- **Request throttling.** Payloads for a parameter are spaced out (configurable,
  default 350 ms) so the extension doesn't produce a DoS-like burst against a
  live authorized target.
- **Timing confirmation.** Time-based hits are re-sent once and must be
  consistently slow before being flagged, reducing false positives from network
  jitter.
- **Settings panel.** Toggle each module on/off and tune the time-based delay,
  timing threshold, and inter-request delay — useful for tuning during a real
  engagement.

> **Authorized use only.** Use this extension only within Burp sessions against
> targets you are explicitly authorized to test, consistent with Burp Suite's own
> usage terms. It is intended for professional, authorized security testing and
> for practice against labs you own.

---

## Build

Requirements: **JDK 17+** and **Maven 3.8+**.

```bash
mvn package
```

The loadable extension jar is written to:

```
target/sqli-auto-detector.jar
```

---

## Load into Burp

1. Open Burp Suite → **Extensions** tab → **Installed** → **Add**.
2. Extension type: **Java**.
3. Select `target/sqli-auto-detector.jar` and click **Next**.
4. The **Output** pane should show `SQLi Auto-Detector (detection only) loaded.`
   and a new **SQLi Detector** tab appears in Burp's top-level tabs.

Detection runs through Burp's normal active scanning pipeline, so trigger it the
way you'd trigger any active audit (e.g. right-click a request →
**Scan** / **Do active scan**, or an audit-configured crawl-and-audit) on hosts
that are in your Target Scope.

---

## How to demo this (safely)

For safe, legal screenshots for a portfolio or interview:

1. Sign in to the **PortSwigger Web Security Academy** and open any of the free
   **SQL injection labs** (e.g. *"SQL injection vulnerability in WHERE clause"* or
   one of the blind-SQLi labs).
2. Add the lab host to Burp's **Target Scope**.
3. Proxy a request that carries an injectable parameter, then run an active scan
   on it.
4. Watch the finding appear both in **Target → Issues** and in the **SQLi
   Detector** tab, with the confidence, payload, and evidence snippet.

Because the Academy labs are provided by PortSwigger for exactly this kind of
practice, they're a safe, authorized place to capture demo material — no
production systems involved.

---

## Project layout

```
pom.xml
src/main/java/com/portfolio/burp/sqlidetector/
├── SqliDetectorExtension.java        # entry point (BurpExtension.initialize)
├── config/
│   └── DetectorConfig.java           # shared, thread-safe settings
├── checks/
│   ├── SqliScanCheck.java            # active ScanCheck: scope gate + orchestration
│   ├── ErrorBasedCheck.java          # module 1
│   ├── BooleanBasedCheck.java        # module 2
│   ├── TimeBasedCheck.java           # module 3
│   ├── ErrorSignatures.java          # curated DB error reference table
│   ├── ModuleResult.java             # per-module outcome
│   └── HttpSupport.java              # request/throttle/response helpers
├── scoring/
│   ├── ConfidenceScorer.java         # combines signals → High/Medium/Low
│   └── Confidence.java               # confidence ↔ Burp severity mapping
├── model/
│   └── Finding.java                  # summary-tab record
└── ui/
    ├── DetectorTab.java              # the suite tab (settings + summary)
    ├── SettingsPanel.java            # module toggles + tuning
    └── SummaryTablePanel.java        # findings table + evidence viewer
```

---

## Tech stack

- **Java 17**
- **PortSwigger Montoya API** (the modern, actively-supported extension API — not
  the legacy Extender API)
- **Maven** for build and packaging
