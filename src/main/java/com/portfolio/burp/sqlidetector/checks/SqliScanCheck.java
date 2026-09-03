package com.portfolio.burp.sqlidetector.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import com.portfolio.burp.sqlidetector.config.DetectorConfig;
import com.portfolio.burp.sqlidetector.model.Finding;
import com.portfolio.burp.sqlidetector.scoring.Confidence;
import com.portfolio.burp.sqlidetector.scoring.ConfidenceScorer;
import com.portfolio.burp.sqlidetector.ui.DetectorTab;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

/**
 * The active scan check. Burp calls {@link #activeAudit} once per insertion
 * point (i.e. per parameter), which is exactly the granularity the detection
 * modules work at.
 *
 * <p>Guardrails enforced here in code, not just docs:
 * <ul>
 *   <li>Nothing runs unless the request URL is inside Burp's Target Scope.</li>
 *   <li>The check <em>stops at detection</em>: it raises an informative issue
 *       and a summary row, and never attempts enumeration or data extraction.</li>
 * </ul>
 */
public final class SqliScanCheck implements ScanCheck {

    /** OWASP WSTG identifier this detector maps to. */
    public static final String WSTG_CODE =
            "WSTG-INPVAL-05 — Testing for SQL Injection";

    private static final String ISSUE_NAME = "Potential SQL injection (detection only)";

    private static final String BACKGROUND =
            "The application appears to build a SQL query using unsanitised input "
                    + "from this parameter. SQL injection can allow reading or modifying "
                    + "database contents and, in some configurations, command execution.<br><br>"
                    + "Mapped to OWASP WSTG: <b>" + WSTG_CODE + "</b>.<br><br>"
                    + "<i>This finding is produced by a detection-only extension. It has not "
                    + "attempted to extract any data. Confirm and exploit manually in "
                    + "Repeater against targets you are authorised to test.</i>";

    private static final String REMEDIATION =
            "Use parameterised queries / prepared statements for all database access. "
                    + "Validate and canonicalise input, apply least-privilege database "
                    + "accounts, and avoid surfacing raw database errors to clients.";

    private final MontoyaApi api;
    private final DetectorConfig config;
    private final DetectorTab tab;

    private final ErrorBasedCheck errorCheck;
    private final BooleanBasedCheck booleanCheck;
    private final TimeBasedCheck timeCheck;
    private final HttpSupport http;

    public SqliScanCheck(MontoyaApi api, DetectorConfig config, DetectorTab tab) {
        this.api = api;
        this.config = config;
        this.tab = tab;
        this.errorCheck = new ErrorBasedCheck(api, config);
        this.booleanCheck = new BooleanBasedCheck(api, config);
        this.timeCheck = new TimeBasedCheck(api, config);
        this.http = new HttpSupport(api, config);
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse,
                                   AuditInsertionPoint auditInsertionPoint) {
        String url = baseRequestResponse.request().url();

        // --- Guardrail 1: scope. Never fire on out-of-scope hosts. ---------
        if (!api.scope().isInScope(url)) {
            return AuditResult.auditResult();
        }

        List<ModuleResult> results = new ArrayList<>();

        if (config.isErrorBasedEnabled()) {
            results.add(errorCheck.analyze(
                    auditInsertionPoint, HttpSupport.bodyOf(baseRequestResponse)));
        }
        if (config.isBooleanBasedEnabled()) {
            results.add(booleanCheck.analyze(auditInsertionPoint, baseRequestResponse));
        }
        if (config.isTimeBasedEnabled()) {
            long baselineMillis = measureBaselineMillis(auditInsertionPoint);
            results.add(timeCheck.analyze(auditInsertionPoint, baselineMillis));
        }

        Confidence confidence = ConfidenceScorer.score(results);
        if (confidence == Confidence.NONE) {
            return AuditResult.auditResult();
        }

        // --- Guardrail 2: stop at detection. Report only. ------------------
        List<ModuleResult> hits = results.stream()
                .filter(ModuleResult::detected)
                .sorted(Comparator.comparingInt(ModuleResult::weight).reversed())
                .collect(Collectors.toList());

        String host = hostOf(url);
        recordSummaryRow(host, auditInsertionPoint.name(), confidence, hits);

        AuditIssue issue = buildIssue(baseRequestResponse, url,
                auditInsertionPoint.name(), confidence, hits);
        return AuditResult.auditResult(issue);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        // Detection is entirely active (it must send probe requests).
        return AuditResult.auditResult();
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        boolean sameName = newIssue.name().equals(existingIssue.name());
        boolean sameUrl = newIssue.baseUrl().equals(existingIssue.baseUrl());
        return (sameName && sameUrl)
                ? ConsolidationAction.KEEP_EXISTING
                : ConsolidationAction.KEEP_BOTH;
    }

    private long measureBaselineMillis(AuditInsertionPoint insertionPoint) {
        // Reproduce the original request (base value, no payload) and time it.
        // Take the faster of two samples to bias against a warm-up outlier.
        HttpSupport.Timed a = http.sendTimed(insertionPoint, insertionPoint.baseValue());
        HttpSupport.Timed b = http.sendTimed(insertionPoint, insertionPoint.baseValue());
        return Math.min(a.elapsedMillis(), b.elapsedMillis());
    }

    private void recordSummaryRow(String host, String parameter,
                                  Confidence confidence, List<ModuleResult> hits) {
        String modules = hits.stream()
                .map(ModuleResult::moduleName)
                .collect(Collectors.joining(", "));
        String payload = hits.isEmpty() ? "" : hits.get(0).payload();
        String evidence = hits.stream()
                .map(h -> "• [" + h.moduleName() + "] " + h.evidence())
                .collect(Collectors.joining("\n"));
        tab.addFinding(new Finding(host, parameter, confidence, modules, payload, evidence));
    }

    private AuditIssue buildIssue(HttpRequestResponse baseRequestResponse, String url,
                                  String parameter, Confidence confidence,
                                  List<ModuleResult> hits) {
        StringBuilder detail = new StringBuilder();
        detail.append("<p>Parameter <b>").append(escape(parameter))
                .append("</b> was flagged as a likely SQL injection point.</p>");
        detail.append("<p>Overall confidence: <b>").append(confidence.name())
                .append("</b> (").append(WSTG_CODE).append(").</p>");
        detail.append("<p>Signals observed:</p><ul>");
        for (ModuleResult h : hits) {
            detail.append("<li><b>").append(escape(h.moduleName())).append("</b>: ")
                    .append(escape(h.evidence()))
                    .append("<br>Payload used: <code>").append(escape(h.payload()))
                    .append("</code></li>");
        }
        detail.append("</ul>");
        detail.append("<p><i>Detection only — no data was extracted. "
                + "Confirm manually in Repeater.</i></p>");

        // Attach the exchanges that demonstrated each signal as evidence.
        List<HttpRequestResponse> evidenceExchanges = new ArrayList<>();
        evidenceExchanges.add(baseRequestResponse);
        for (ModuleResult h : hits) {
            if (h.evidenceExchange() != null) {
                evidenceExchanges.add(h.evidenceExchange());
            }
        }

        return AuditIssue.auditIssue(
                ISSUE_NAME,
                detail.toString(),
                REMEDIATION,
                url,
                confidence.severity(),
                confidence.issueConfidence(),
                BACKGROUND,
                REMEDIATION,
                confidence.severity(),
                evidenceExchanges.toArray(new HttpRequestResponse[0]));
    }

    private static String hostOf(String url) {
        try {
            return java.net.URI.create(url).getHost();
        } catch (Exception e) {
            return url;
        }
    }

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }
}
