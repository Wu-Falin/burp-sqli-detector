package com.portfolio.burp.sqlidetector.ui;

import com.portfolio.burp.sqlidetector.model.Finding;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;

/**
 * Read-only summary of every flagged parameter, one row per finding, with the
 * full evidence shown for the selected row. This mirrors what is also raised as
 * a native Burp scanner issue, in a single at-a-glance table.
 */
public final class SummaryTablePanel extends JPanel {

    private static final String[] COLUMNS =
            {"Time", "Host", "Parameter", "Confidence", "Modules", "Payload"};

    private final DefaultTableModel tableModel;
    private final JTextArea evidenceArea;
    private final List<Finding> findings = new ArrayList<>();

    public SummaryTablePanel() {
        super(new BorderLayout());

        tableModel = new DefaultTableModel(COLUMNS, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

        evidenceArea = new JTextArea(6, 60);
        evidenceArea.setEditable(false);
        evidenceArea.setLineWrap(true);
        evidenceArea.setWrapStyleWord(true);
        evidenceArea.setBorder(BorderFactory.createTitledBorder("Evidence"));

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) {
                return;
            }
            int row = table.getSelectedRow();
            if (row >= 0 && row < findings.size()) {
                Finding f = findings.get(row);
                evidenceArea.setText(f.evidence());
                evidenceArea.setCaretPosition(0);
            }
        });

        JButton clearButton = new JButton("Clear findings");
        clearButton.addActionListener(e -> clear());
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        toolbar.add(clearButton);

        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table),
                new JScrollPane(evidenceArea));
        split.setResizeWeight(0.75);

        add(toolbar, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
    }

    /** Adds a finding to the table. Safe to call from any thread. */
    public void addFinding(Finding f) {
        SwingUtilities.invokeLater(() -> {
            findings.add(f);
            tableModel.addRow(new Object[]{
                    f.time(), f.host(), f.parameter(),
                    f.confidence().name(), f.modules(), f.payload()
            });
        });
    }

    private void clear() {
        SwingUtilities.invokeLater(() -> {
            findings.clear();
            tableModel.setRowCount(0);
            evidenceArea.setText("");
        });
    }
}
