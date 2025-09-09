package ch.admin.bj.swiyu.didtoolbox.webvh;

/**
 * The class {@code WebVerifiableHistoryDeactivatorException} is a <em>checked exception</em> class indicating conditions related to
 * {@code WebVerifiableHistoryDeactivator} class that any reasonable application might want to catch.
 *
 * @see WebVerifiableHistoryDeactivator
 */
public class WebVerifiableHistoryDeactivatorException extends Exception {
    public WebVerifiableHistoryDeactivatorException(String message) {
        super(message);
    }

    public WebVerifiableHistoryDeactivatorException(Exception e) {
        super(e);
    }

    public WebVerifiableHistoryDeactivatorException(String message, Throwable cause) {
        super(message, cause);
    }
}