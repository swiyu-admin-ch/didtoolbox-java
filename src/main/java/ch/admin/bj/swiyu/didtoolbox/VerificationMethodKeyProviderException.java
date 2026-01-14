package ch.admin.bj.swiyu.didtoolbox;

/**
 * The class {@link VerificationMethodKeyProviderException} is a <em>checked exception</em> class indicating conditions related to
 * {@link VerificationMethodKeyProvider} class that any reasonable application might want to catch.
 *
 * @see VerificationMethodKeyProvider
 */
public class VerificationMethodKeyProviderException extends Exception {
    public VerificationMethodKeyProviderException(String message) {
        super(message);
    }

    public VerificationMethodKeyProviderException(Exception e) {
        super(e);
    }

    public VerificationMethodKeyProviderException(String message, Throwable cause) {
        super(message, cause);
    }
}