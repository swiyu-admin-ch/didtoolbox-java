package ch.admin.bj.swiyu.didtoolbox.model;

/**
 * The class {@link VerificationMethodException} is a <em>checked exception</em> class indicating conditions related to
 * any {@link VerificationMethod} interface implementation, that any reasonable application might want to catch.
 *
 * @see VerificationMethod
 */
public class VerificationMethodException extends Exception {
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