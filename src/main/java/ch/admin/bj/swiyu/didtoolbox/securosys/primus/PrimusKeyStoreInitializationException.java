package ch.admin.bj.swiyu.didtoolbox.securosys.primus;

import java.io.Serial;

/**
 * The class {@code SecurosysPrimusKeyStoreInitializationException} is a <em>checked exception</em> class indicating conditions related to
 * {@code SecurosysPrimusKeyStoreLoader} class that any reasonable application might want to catch.
 *
 * @see PrimusKeyStoreLoader
 */
public class PrimusKeyStoreInitializationException extends Exception {

    @Serial
    private static final long serialVersionUID = 1823339001865821043L;

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