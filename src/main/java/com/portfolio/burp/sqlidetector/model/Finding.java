package com.portfolio.burp.sqlidetector.model;

import com.portfolio.burp.sqlidetector.scoring.Confidence;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * A single flagged parameter, as shown in the extension's summary tab.
 *
 * <p>Purely a detection record: it names where a potential injection point was
 * seen and why, and never carries any extracted data.
 */
public final class Finding {

    private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");

    private final String time;
    private final String host;
    private final String parameter;
    private final Confidence confidence;
    private final String modules;
    private final String payload;
    private final String evidence;

    public Finding(String host, String parameter, Confidence confidence,
                   String modules, String payload, String evidence) {
        this.time = LocalTime.now().format(TIME_FMT);
        this.host = host;
        this.parameter = parameter;
        this.confidence = confidence;
        this.modules = modules;
        this.payload = payload;
        this.evidence = evidence;
    }

    public String time() {
        return time;
    }

    public String host() {
        return host;
    }

    public String parameter() {
        return parameter;
    }

    public Confidence confidence() {
        return confidence;
    }

    public String modules() {
        return modules;
    }

    public String payload() {
        return payload;
    }

    public String evidence() {
        return evidence;
    }
}
