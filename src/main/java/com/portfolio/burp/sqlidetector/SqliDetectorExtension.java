package com.portfolio.burp.sqlidetector;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import com.portfolio.burp.sqlidetector.checks.SqliScanCheck;
import com.portfolio.burp.sqlidetector.config.DetectorConfig;
import com.portfolio.burp.sqlidetector.ui.DetectorTab;

/**
 * Extension entry point.
 *
 * <p>Burp discovers this class via the {@code Montoya Extension} attribute in the
 * jar manifest (added automatically by the Montoya API for classes implementing
 * {@link BurpExtension}) and calls {@link #initialize(MontoyaApi)} once at load.
 *
 * <p>Wiring is deliberately small: build the shared config, the UI tab, and
 * register a single active {@link SqliScanCheck}. All detection happens through
 * Burp's own scanner pipeline, so scope handling, throttling hooks, and issue
 * display are consistent with the rest of Burp.
 */
public final class SqliDetectorExtension implements BurpExtension {

    private static final String EXTENSION_NAME = "SQLi Auto-Detector (detection only)";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(EXTENSION_NAME);

        DetectorConfig config = new DetectorConfig();
        DetectorTab tab = new DetectorTab(config);

        api.userInterface().registerSuiteTab("SQLi Detector", tab);
        api.scanner().registerScanCheck(new SqliScanCheck(api, config, tab));

        api.logging().logToOutput(EXTENSION_NAME + " loaded.");
        api.logging().logToOutput(
                "Detection-only: flags likely SQLi in in-scope traffic; "
                        + "performs no data extraction. Mapped to "
                        + SqliScanCheck.WSTG_CODE + ".");
    }
}
