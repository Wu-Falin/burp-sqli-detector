package com.portfolio.burp.sqlidetector.config;

/**
 * Shared, mutable configuration for the detection modules.
 *
 * <p>The settings panel writes to this object and the scan check reads from it,
 * so all fields are accessed with {@code volatile} / synchronised semantics to
 * stay safe across Burp's scanner threads and the Swing event thread.
 */
public final class DetectorConfig {

    // --- Module toggles (all on by default) -------------------------------
    private volatile boolean errorBasedEnabled = true;
    private volatile boolean booleanBasedEnabled = true;
    private volatile boolean timeBasedEnabled = true;

    // --- Time-based tuning -------------------------------------------------
    /** Delay (seconds) requested in SLEEP/WAITFOR/pg_sleep payloads. */
    private volatile int timeDelaySeconds = 5;

    /**
     * How much slower (milliseconds) than the baseline a response must be
     * before it counts as a timing hit. Keeps normal latency from tripping it.
     */
    private volatile int timeThresholdMillis = 3500;

    // --- Safety / throttling ----------------------------------------------
    /**
     * Pause between individual payload requests for a single parameter. Spacing
     * requests out avoids a DoS-like burst against an authorised live target.
     */
    private volatile int requestDelayMillis = 350;

    public boolean isErrorBasedEnabled() {
        return errorBasedEnabled;
    }

    public void setErrorBasedEnabled(boolean errorBasedEnabled) {
        this.errorBasedEnabled = errorBasedEnabled;
    }

    public boolean isBooleanBasedEnabled() {
        return booleanBasedEnabled;
    }

    public void setBooleanBasedEnabled(boolean booleanBasedEnabled) {
        this.booleanBasedEnabled = booleanBasedEnabled;
    }

    public boolean isTimeBasedEnabled() {
        return timeBasedEnabled;
    }

    public void setTimeBasedEnabled(boolean timeBasedEnabled) {
        this.timeBasedEnabled = timeBasedEnabled;
    }

    public int getTimeDelaySeconds() {
        return timeDelaySeconds;
    }

    public void setTimeDelaySeconds(int timeDelaySeconds) {
        this.timeDelaySeconds = timeDelaySeconds;
    }

    public int getTimeThresholdMillis() {
        return timeThresholdMillis;
    }

    public void setTimeThresholdMillis(int timeThresholdMillis) {
        this.timeThresholdMillis = timeThresholdMillis;
    }

    public int getRequestDelayMillis() {
        return requestDelayMillis;
    }

    public void setRequestDelayMillis(int requestDelayMillis) {
        this.requestDelayMillis = requestDelayMillis;
    }
}
