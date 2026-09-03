package com.portfolio.burp.sqlidetector.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import com.portfolio.burp.sqlidetector.config.DetectorConfig;

import java.util.List;
import java.util.Optional;

/**
 * Error-based detection.
 *
 * <p>Injects a small set of syntax-breaking probe characters and looks for a
 * known database error signature in the response. A match is the strongest of
 * the three signals: it means our input reached — and broke — a SQL parser.
 */
public final class ErrorBasedCheck {

    public static final String MODULE_NAME = "Error-based";
    private static final int WEIGHT = 3;

    /** Curated probe set — enough to trip a parser, not a fuzzing dictionary. */
    private static final List<String> PROBES = List.of("'", "\"", "\\", "';--");

    private final HttpSupport http;
    private final MontoyaApi api;

    public ErrorBasedCheck(MontoyaApi api, DetectorConfig config) {
        this.api = api;
        this.http = new HttpSupport(api, config);
    }

    public ModuleResult analyze(AuditInsertionPoint insertionPoint, String baseBody) {
        for (String probe : PROBES) {
            String payload = insertionPoint.baseValue() + probe;
            HttpRequestResponse rr = http.send(insertionPoint, payload);
            if (!HttpSupport.hasResponse(rr)) {
                continue;
            }

            String body = HttpSupport.bodyOf(rr);
            Optional<String> match = ErrorSignatures.findMatch(body);

            // Only flag an error that appears *because* of our probe: if the same
            // signature already shows in the untouched baseline, it isn't ours.
            if (match.isPresent() && ErrorSignatures.findMatch(baseBody).isEmpty()) {
                String evidence = "DB error signature triggered by probe "
                        + "\"" + probe + "\" — " + match.get();
                api.logging().logToOutput("[Error-based] hit on '"
                        + insertionPoint.name() + "' with probe " + probe);
                return ModuleResult.hit(MODULE_NAME, WEIGHT, payload, evidence, rr);
            }
        }
        return ModuleResult.miss(MODULE_NAME);
    }
}
