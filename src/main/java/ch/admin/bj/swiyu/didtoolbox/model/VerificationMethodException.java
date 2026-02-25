package ch.admin.bj.swiyu.didtoolbox.model;

import java.io.Serial;

/**
 * The class {@link VerificationMethodException} is a <em>checked exception</em> class indicating conditions related to
 * any {@link VerificationMethod} interface implementation, that any reasonable application might want to catch.
 *
 * @see VerificationMethod
 */
public class VerificationMethodException extends Exception {

    @Serial
    private static final long serialVersionUID = -3096430759297197325L;

    public VerificationMethodException(String message) {
        super(message);
    }

    public VerificationMethodException(Exception e) {
        super(e);
    }

    public VerificationMethodException(String message, Throwable cause) {
        super(message, cause);
    }
}