package com.portfolio.burp.sqlidetector.scoring;

import com.portfolio.burp.sqlidetector.checks.ModuleResult;

import java.util.List;

/**
 * Combines the per-module signals for one parameter into a single confidence
 * bucket.
 *
 * <p>Each module carries a weight (error-based 3, boolean 2, time 2). The
 * weights of the modules that fired are summed:
 * <ul>
 *   <li>a definitive error signature (>=3) → HIGH;</li>
 *   <li>two independent blind signals agreeing (4) → HIGH;</li>
 *   <li>a single blind signal (2) → MEDIUM;</li>
 *   <li>anything weaker → LOW; nothing → NONE.</li>
 * </ul>
 */
public final class ConfidenceScorer {

    private ConfidenceScorer() {
    }

    public static Confidence score(List<ModuleResult> results) {
        int total = results.stream()
                .filter(ModuleResult::detected)
                .mapToInt(ModuleResult::weight)
                .sum();

        if (total >= 3) {
            return Confidence.HIGH;
        }
        if (total == 2) {
            return Confidence.MEDIUM;
        }
        if (total >= 1) {
            return Confidence.LOW;
        }
        return Confidence.NONE;
    }
}
