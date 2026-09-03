package com.portfolio.burp.sqlidetector.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import com.portfolio.burp.sqlidetector.config.DetectorConfig;

/**
 * Shared helpers for the detection modules: building a payload request from an
 * insertion point, sending it with throttling, and measuring/reading responses.
 */
final class HttpSupport {

    private final MontoyaApi api;
    private final DetectorConfig config;

    HttpSupport(MontoyaApi api, DetectorConfig config) {
        this.api = api;
        this.config = config;
    }

    /**
     * Sends {@code payload} injected at the given insertion point, after pausing
     * for the configured inter-request delay so we never burst the target.
     */
    HttpRequestResponse send(AuditInsertionPoint insertionPoint, String payload) {
        throttle();
        HttpRequest request =
                insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
        return api.http().sendRequest(request);
    }

    /** Same as {@link #send} but also returns wall-clock elapsed time in millis. */
    Timed sendTimed(AuditInsertionPoint insertionPoint, String payload) {
        throttle();
        HttpRequest request =
                insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
        long start = System.nanoTime();
        HttpRequestResponse rr = api.http().sendRequest(request);
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;
        return new Timed(rr, elapsedMillis);
    }

    static boolean hasResponse(HttpRequestResponse rr) {
        return rr != null && rr.response() != null;
    }

    static String bodyOf(HttpRequestResponse rr) {
        return hasResponse(rr) ? rr.response().bodyToString() : "";
    }

    static int bodyLengthOf(HttpRequestResponse rr) {
        return hasResponse(rr) ? rr.response().body().length() : -1;
    }

    static int statusOf(HttpRequestResponse rr) {
        return hasResponse(rr) ? rr.response().statusCode() : -1;
    }

    /** Truncates arbitrary evidence text to a short, log-friendly snippet. */
    static String snippet(String text, int max) {
        if (text == null) {
            return "";
        }
        String flat = text.replaceAll("\\s+", " ").trim();
        return flat.length() <= max ? flat : flat.substring(0, max) + "…";
    }

    private void throttle() {
        int delay = config.getRequestDelayMillis();
        if (delay > 0) {
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** A response paired with how long the round-trip took. */
    record Timed(HttpRequestResponse response, long elapsedMillis) {
    }
}
