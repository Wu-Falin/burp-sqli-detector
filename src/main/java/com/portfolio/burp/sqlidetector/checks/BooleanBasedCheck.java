package com.portfolio.burp.sqlidetector.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import com.portfolio.burp.sqlidetector.config.DetectorConfig;

/**
 * Boolean-based blind detection.
 *
 * <p>Sends a logically-true condition ({@code ' AND 1=1-- }) and a logically-
 * false one ({@code ' AND 1=2-- }). If the application is building SQL from the
 * parameter, the TRUE response tends to match the baseline while the FALSE
 * response diverges (different length and/or status). That asymmetry — true
 * ≈ baseline, false ≠ baseline — is the signal.
 */
public final class BooleanBasedCheck {

    public static final String MODULE_NAME = "Boolean-based";
    private static final int WEIGHT = 2;

    private static final String TRUE_PAYLOAD = "' AND 1=1-- ";
    private static final String FALSE_PAYLOAD = "' AND 1=2-- ";

    /** Minimum body-length delta (bytes) before a difference counts as real. */
    private static final int LENGTH_DELTA_THRESHOLD = 24;

    private final HttpSupport http;
    private final MontoyaApi api;

    public BooleanBasedCheck(MontoyaApi api, DetectorConfig config) {
        this.api = api;
        this.http = new HttpSupport(api, config);
    }

    public ModuleResult analyze(AuditInsertionPoint insertionPoint, HttpRequestResponse baseline) {
        int baseLen = HttpSupport.bodyLengthOf(baseline);
        int baseStatus = HttpSupport.statusOf(baseline);
        if (baseLen < 0) {
            return ModuleResult.miss(MODULE_NAME);
        }

        HttpRequestResponse truthy =
                http.send(insertionPoint, insertionPoint.baseValue() + TRUE_PAYLOAD);
        HttpRequestResponse falsy =
                http.send(insertionPoint, insertionPoint.baseValue() + FALSE_PAYLOAD);

        if (!HttpSupport.hasResponse(truthy) || !HttpSupport.hasResponse(falsy)) {
            return ModuleResult.miss(MODULE_NAME);
        }

        int trueLen = HttpSupport.bodyLengthOf(truthy);
        int falseLen = HttpSupport.bodyLengthOf(falsy);
        int trueStatus = HttpSupport.statusOf(truthy);
        int falseStatus = HttpSupport.statusOf(falsy);

        boolean trueMatchesBaseline =
                trueStatus == baseStatus
                        && Math.abs(trueLen - baseLen) < LENGTH_DELTA_THRESHOLD;
        boolean falseDiffersFromTrue =
                falseStatus != trueStatus
                        || Math.abs(falseLen - trueLen) >= LENGTH_DELTA_THRESHOLD;

        if (trueMatchesBaseline && falseDiffersFromTrue) {
            String evidence = String.format(
                    "TRUE (1=1) ≈ baseline [status %d, %d bytes]; "
                            + "FALSE (1=2) diverges [status %d, %d bytes]. "
                            + "Baseline was status %d, %d bytes.",
                    trueStatus, trueLen, falseStatus, falseLen, baseStatus, baseLen);
            api.logging().logToOutput("[Boolean-based] hit on '" + insertionPoint.name() + "'");
            // The FALSE exchange is the more illustrative evidence to attach.
            return ModuleResult.hit(MODULE_NAME, WEIGHT,
                    insertionPoint.baseValue() + FALSE_PAYLOAD, evidence, falsy);
        }
        return ModuleResult.miss(MODULE_NAME);
    }
}
