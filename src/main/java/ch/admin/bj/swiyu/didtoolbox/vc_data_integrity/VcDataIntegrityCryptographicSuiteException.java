package ch.admin.bj.swiyu.didtoolbox.vc_data_integrity;

/**
 * The class {@link VcDataIntegrityCryptographicSuiteException} is a <em>checked exception</em> class indicating conditions related to
 * any {@link VcDataIntegrityCryptographicSuite} implementation that any reasonable application might want to catch.
 *
 * @see VcDataIntegrityCryptographicSuite
 * @since 1.8.0
 */
public class VcDataIntegrityCryptographicSuiteException extends Exception {
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