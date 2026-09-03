package com.portfolio.burp.sqlidetector.ui;

import com.portfolio.burp.sqlidetector.config.DetectorConfig;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.SpinnerNumberModel;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;

/**
 * Settings panel: toggle each detection module and tune the time-based
 * threshold and request spacing. All controls write straight through to the
 * shared {@link DetectorConfig} the scan check reads from.
 */
public final class SettingsPanel extends JPanel {

    public SettingsPanel(DetectorConfig config) {
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createTitledBorder("Detection settings"));

        add(intro());
        add(Box.createVerticalStrut(8));

        // --- Module toggles ------------------------------------------------
        JCheckBox errorToggle = new JCheckBox("Error-based detection", config.isErrorBasedEnabled());
        errorToggle.addActionListener(e -> config.setErrorBasedEnabled(errorToggle.isSelected()));

        JCheckBox booleanToggle = new JCheckBox("Boolean-based blind detection", config.isBooleanBasedEnabled());
        booleanToggle.addActionListener(e -> config.setBooleanBasedEnabled(booleanToggle.isSelected()));

        JCheckBox timeToggle = new JCheckBox("Time-based blind detection", config.isTimeBasedEnabled());
        timeToggle.addActionListener(e -> config.setTimeBasedEnabled(timeToggle.isSelected()));

        add(leftRow(errorToggle));
        add(leftRow(booleanToggle));
        add(leftRow(timeToggle));
        add(Box.createVerticalStrut(8));

        // --- Time-based tuning ---------------------------------------------
        JSpinner delaySpinner = new JSpinner(
                new SpinnerNumberModel(config.getTimeDelaySeconds(), 1, 30, 1));
        delaySpinner.addChangeListener(e ->
                config.setTimeDelaySeconds((Integer) delaySpinner.getValue()));

        JSpinner thresholdSpinner = new JSpinner(
                new SpinnerNumberModel(config.getTimeThresholdMillis(), 500, 20000, 250));
        thresholdSpinner.addChangeListener(e ->
                config.setTimeThresholdMillis((Integer) thresholdSpinner.getValue()));

        add(labelled("Injected delay (seconds):", delaySpinner));
        add(labelled("Timing hit threshold (ms):", thresholdSpinner));
        add(Box.createVerticalStrut(8));

        // --- Throttle ------------------------------------------------------
        JSpinner throttleSpinner = new JSpinner(
                new SpinnerNumberModel(config.getRequestDelayMillis(), 0, 5000, 50));
        throttleSpinner.addChangeListener(e ->
                config.setRequestDelayMillis((Integer) throttleSpinner.getValue()));
        add(labelled("Delay between requests (ms):", throttleSpinner));
    }

    private static JPanel intro() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel label = new JLabel("<html><b>Detection only.</b> This extension flags "
                + "likely SQLi points in in-scope traffic. It never enumerates or "
                + "extracts data — confirm and exploit manually in Repeater.</html>");
        label.setPreferredSize(new Dimension(560, 40));
        p.add(label);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private static JPanel leftRow(Component c) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        p.add(c);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }

    private static JPanel labelled(String text, Component control) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JLabel label = new JLabel(text);
        label.setPreferredSize(new Dimension(220, 24));
        p.add(label);
        p.add(control);
        p.setAlignmentX(Component.LEFT_ALIGNMENT);
        return p;
    }
}
