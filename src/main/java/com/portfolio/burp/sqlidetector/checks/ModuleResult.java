package com.portfolio.burp.sqlidetector.checks;

import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Outcome of a single detection module against a single parameter.
 *
 * <p>A module produces exactly one of these. When {@link #detected()} is false
 * the other fields simply describe what was tried (useful for logging); when it
 * is true they carry the payload and human-readable evidence that back the
 * finding, plus the request/response that demonstrated it.
 */
public final class ModuleResult {

    private final String moduleName;
    private final boolean detected;
    private final int weight;
    private final String payload;
    private final String evidence;
    private final HttpRequestResponse evidenceExchange;

    private ModuleResult(String moduleName, boolean detected, int weight,
                         String payload, String evidence,
                         HttpRequestResponse evidenceExchange) {
        this.moduleName = moduleName;
        this.detected = detected;
        this.weight = weight;
        this.payload = payload;
        this.evidence = evidence;
        this.evidenceExchange = evidenceExchange;
    }

    /** A positive hit, carrying the evidence that supports it. */
    public static ModuleResult hit(String moduleName, int weight, String payload,
                                   String evidence, HttpRequestResponse evidenceExchange) {
        return new ModuleResult(moduleName, true, weight, payload, evidence, evidenceExchange);
    }

    /** No signal from this module. */
    public static ModuleResult miss(String moduleName) {
        return new ModuleResult(moduleName, false, 0, null, null, null);
    }

    public String moduleName() {
        return moduleName;
    }

    public boolean detected() {
        return detected;
    }

    public int weight() {
        return weight;
    }

    public String payload() {
        return payload;
    }

    public String evidence() {
        return evidence;
    }

    public HttpRequestResponse evidenceExchange() {
        return evidenceExchange;
    }
}
