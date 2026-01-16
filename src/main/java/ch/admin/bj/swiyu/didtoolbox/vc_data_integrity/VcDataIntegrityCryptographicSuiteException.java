package ch.admin.bj.swiyu.didtoolbox.vc_data_integrity;

import java.io.Serial;

/**
 * The class {@link VcDataIntegrityCryptographicSuiteException} is a <em>checked exception</em> class indicating conditions related to
 * any {@link VcDataIntegrityCryptographicSuite} implementation that any reasonable application might want to catch.
 *
 * @see VcDataIntegrityCryptographicSuite
 * @since 1.8.0
 */
public class VcDataIntegrityCryptographicSuiteException extends Exception {
    @Serial
    private static final long serialVersionUID = 6090505936971791930L;

    public VcDataIntegrityCryptographicSuiteException(String message) {
        super(message);
    }

    public VcDataIntegrityCryptographicSuiteException(Exception e) {
        super(e);
    }

    public VcDataIntegrityCryptographicSuiteException(String message, Throwable cause) {
        super(message, cause);
    }
}