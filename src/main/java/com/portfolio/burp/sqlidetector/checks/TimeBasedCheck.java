package com.portfolio.burp.sqlidetector.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import com.portfolio.burp.sqlidetector.config.DetectorConfig;

import java.util.List;

/**
 * Time-based blind detection.
 *
 * <p>Sends database-specific delay payloads and measures the round-trip time.
 * Because timing is the noisiest of the three signals, a candidate delay is
 * always confirmed with a second request before it is flagged, and every
 * finding is labelled "verify manually".
 */
public final class TimeBasedCheck {

    public static final String MODULE_NAME = "Time-based";
    private static final int WEIGHT = 2;

    private final HttpSupport http;
    private final MontoyaApi api;
    private final DetectorConfig config;

    public TimeBasedCheck(MontoyaApi api, DetectorConfig config) {
        this.api = api;
        this.config = config;
        this.http = new HttpSupport(api, config);
    }

    /** A delay payload template with a {@code %d}-style seconds placeholder. */
    private record DelayPayload(String engine, String template) {
        String render(String base, int seconds) {
            return base + String.format(template, seconds);
        }
    }

    private static List<DelayPayload> payloads() {
        return List.of(
                new DelayPayload("MySQL", "' AND SLEEP(%d)-- "),
                new DelayPayload("MSSQL", "'; WAITFOR DELAY '0:0:%d'-- "),
                new DelayPayload("PostgreSQL", "' AND pg_sleep(%d)-- ")
        );
    }

    public ModuleResult analyze(AuditInsertionPoint insertionPoint, long baselineMillis) {
        int seconds = config.getTimeDelaySeconds();
        int threshold = config.getTimeThresholdMillis();
        // A hit must exceed the baseline by roughly the injected delay, tempered
        // by the configured threshold so ordinary latency never trips it.
        long expectedFloor = baselineMillis + Math.min((long) seconds * 1000L, threshold);

        for (DelayPayload dp : payloads()) {
            String payload = dp.render(insertionPoint.baseValue(), seconds);

            HttpSupport.Timed first = http.sendTimed(insertionPoint, payload);
            if (first.elapsedMillis() < expectedFloor) {
                continue; // fast response -> no delay -> not this engine
            }

            // Candidate delay: confirm once to rule out a one-off network stall.
            HttpSupport.Timed second = http.sendTimed(insertionPoint, payload);
            if (second.elapsedMillis() >= expectedFloor) {
                String evidence = String.format(
                        "%s delay payload produced consistent slow responses: "
                                + "%d ms then %d ms (baseline ~%d ms, injected delay %ds). "
                                + "Timing-based — verify manually.",
                        dp.engine(), first.elapsedMillis(), second.elapsedMillis(),
                        baselineMillis, seconds);
                api.logging().logToOutput("[Time-based] hit on '"
                        + insertionPoint.name() + "' (" + dp.engine() + ")");
                return ModuleResult.hit(MODULE_NAME, WEIGHT, payload, evidence, second.response());
            }
        }
        return ModuleResult.miss(MODULE_NAME);
    }
}
