package com.portfolio.burp.sqlidetector.checks;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Small, curated reference table of database error substrings.
 *
 * <p>This is intentionally conservative — a handful of high-signal strings per
 * engine rather than an exhaustive dictionary. Matching one of these in a
 * response body is a strong indicator that unsanitised input reached a SQL
 * parser.
 */
public final class ErrorSignatures {

    /** Engine name -> representative error substrings (matched case-insensitively). */
    private static final Map<String, List<String>> SIGNATURES = Map.of(
            "MySQL", List.of(
                    "you have an error in your sql syntax",
                    "warning: mysql",
                    "mysql_fetch",
                    "mysqli_",
                    "com.mysql.jdbc",
                    "check the manual that corresponds to your mysql server version"
            ),
            "MSSQL", List.of(
                    "unclosed quotation mark after the character string",
                    "microsoft ole db provider for sql server",
                    "microsoft sql native client",
                    "incorrect syntax near",
                    "com.microsoft.sqlserver.jdbc"
            ),
            "PostgreSQL", List.of(
                    "pg_query()",
                    "pg_exec()",
                    "unterminated quoted string at or near",
                    "syntax error at or near",
                    "org.postgresql.util.psqlexception"
            ),
            "Oracle", List.of(
                    "ora-00933",
                    "ora-00921",
                    "ora-01756",
                    "quoted string not properly terminated",
                    "oracle.jdbc"
            ),
            "SQLite", List.of(
                    "sqlite3::",
                    "sqlite_error",
                    "unrecognized token:",
                    "sqlitexception",
                    "near \"" // e.g. near "'": syntax error
            )
    );

    private ErrorSignatures() {
    }

    /**
     * Scans {@code responseBody} for any known error signature.
     *
     * @return the first match as "Engine: <matched substring>", or empty if none.
     */
    public static Optional<String> findMatch(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return Optional.empty();
        }
        String haystack = responseBody.toLowerCase();
        for (Map.Entry<String, List<String>> entry : SIGNATURES.entrySet()) {
            for (String needle : entry.getValue()) {
                if (haystack.contains(needle)) {
                    return Optional.of(entry.getKey() + ": \"" + needle + "\"");
                }
            }
        }
        return Optional.empty();
    }
}
