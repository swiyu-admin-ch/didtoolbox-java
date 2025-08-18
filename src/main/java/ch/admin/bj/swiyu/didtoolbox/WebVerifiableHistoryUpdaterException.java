package ch.admin.bj.swiyu.didtoolbox;

/**
 * The class {@link WebVerifiableHistoryUpdaterException} is a <em>checked exception</em> class indicating conditions related to
 * {@link WebVerifiableHistoryUpdater} class that any reasonable application might want to catch.
 *
 * @see WebVerifiableHistoryUpdater
 */
public class WebVerifiableHistoryUpdaterException extends Exception {
    public WebVerifiableHistoryUpdaterException(String message) {
        super(message);
    }

    public WebVerifiableHistoryUpdaterException(Exception e) {
        super(e);
    }

    public WebVerifiableHistoryUpdaterException(String message, Throwable cause) {
        super(message, cause);
    }
}