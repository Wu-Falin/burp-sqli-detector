package com.portfolio.burp.sqlidetector.ui;

import com.portfolio.burp.sqlidetector.config.DetectorConfig;
import com.portfolio.burp.sqlidetector.model.Finding;

import javax.swing.JPanel;
import java.awt.BorderLayout;

/**
 * The single suite tab shown in Burp: settings on top, live findings summary
 * below. Registered via {@code userInterface().registerSuiteTab(...)}.
 */
public final class DetectorTab extends JPanel {

    private final SummaryTablePanel summaryPanel;

    public DetectorTab(DetectorConfig config) {
        super(new BorderLayout());
        SettingsPanel settingsPanel = new SettingsPanel(config);
        this.summaryPanel = new SummaryTablePanel();

        add(settingsPanel, BorderLayout.NORTH);
        add(summaryPanel, BorderLayout.CENTER);
    }

    /** Records a finding in the summary table. Thread-safe. */
    public void addFinding(Finding finding) {
        summaryPanel.addFinding(finding);
    }
}
