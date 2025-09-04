package ch.admin.bj.swiyu.didtoolbox.webvh;

/**
 * The class {@link WebVerifiableHistoryCreatorException} is a <em>checked exception</em> class indicating conditions related to
 * {@link WebVerifiableHistoryCreator} class that any reasonable application might want to catch.
 *
 * @see WebVerifiableHistoryCreator
 */
public class WebVerifiableHistoryCreatorException extends Exception {
    public WebVerifiableHistoryCreatorException(String message) {
        super(message);
    }

    public WebVerifiableHistoryCreatorException(Exception e) {
        super(e);
    }

    public WebVerifiableHistoryCreatorException(String message, Throwable cause) {
        super(message, cause);
    }
}