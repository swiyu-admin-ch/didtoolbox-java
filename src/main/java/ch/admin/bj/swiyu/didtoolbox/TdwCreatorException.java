package ch.admin.bj.swiyu.didtoolbox;

/**
 * The {@link TdwCreatorException} is thrown to indicate that DID log creation has failed.
 */
public class TdwCreatorException extends Exception {

    public TdwCreatorException(String message) {
        super(message);
    }

    public TdwCreatorException(String message, Throwable cause) {
        super(message, cause);
    }

    public TdwCreatorException(Throwable cause) {
        super(cause);
    }
}
