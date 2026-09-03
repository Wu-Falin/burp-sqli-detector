package com.portfolio.burp.sqlidetector.scoring;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

/**
 * Overall confidence bucket for a flagged parameter, plus the mapping onto
 * Burp's native severity/confidence enums used when raising scanner issues.
 */
public enum Confidence {

    HIGH(AuditIssueSeverity.HIGH, AuditIssueConfidence.FIRM),
    MEDIUM(AuditIssueSeverity.MEDIUM, AuditIssueConfidence.TENTATIVE),
    LOW(AuditIssueSeverity.LOW, AuditIssueConfidence.TENTATIVE),
    NONE(AuditIssueSeverity.INFORMATION, AuditIssueConfidence.TENTATIVE);

    private final AuditIssueSeverity severity;
    private final AuditIssueConfidence issueConfidence;

    Confidence(AuditIssueSeverity severity, AuditIssueConfidence issueConfidence) {
        this.severity = severity;
        this.issueConfidence = issueConfidence;
    }

    public AuditIssueSeverity severity() {
        return severity;
    }

    public AuditIssueConfidence issueConfidence() {
        return issueConfidence;
    }
}
