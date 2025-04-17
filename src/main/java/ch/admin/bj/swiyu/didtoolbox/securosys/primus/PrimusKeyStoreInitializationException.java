package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

/**
 * The class {@code SecurosysPrimusKeyStoreInitializationException} is a <em>checked exception</em> class indicating conditions related to
 * {@code SecurosysPrimusKeyStoreLoader} class that any reasonable application might want to catch.
 *
 * @see PrimusKeyStoreLoader
 */
public class PrimusKeyStoreInitializationException extends Exception {
    public PrimusKeyStoreInitializationException(String message) {
        super(message);
    }

    public PrimusKeyStoreInitializationException(Exception e) {
        super(e);
    }

    public PrimusKeyStoreInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}