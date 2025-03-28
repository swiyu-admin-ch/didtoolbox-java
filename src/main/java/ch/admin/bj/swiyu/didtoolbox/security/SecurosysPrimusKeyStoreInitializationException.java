package ch.admin.bj.swiyu.didtoolbox.security;

/**
 * The class {@code SecurosysPrimusKeyStoreInitializationException} is a <em>checked exception</em> class indicating conditions related to
 * {@code SecurosysPrimusKeyStoreLoader} class that any reasonable application might want to catch.
 *
 * @see SecurosysPrimusKeyStoreLoader
 */
public class SecurosysPrimusKeyStoreInitializationException extends Exception {
    public SecurosysPrimusKeyStoreInitializationException(String message) {
        super(message);
    }

    public SecurosysPrimusKeyStoreInitializationException(Exception e) {
        super(e);
    }

    public SecurosysPrimusKeyStoreInitializationException(String message, Throwable cause) {
        super(message, cause);
    }
}