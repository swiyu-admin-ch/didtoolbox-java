package ch.admin.bj.swiyu.didtoolbox;

/**
 * The class {@link TdwUpdaterException} is a <em>checked exception</em> class indicating conditions related to
 * {@link TdwUpdater} class that any reasonable application might want to catch.
 *
 * @see TdwUpdater
 */
public class TdwUpdaterException extends Exception {
    public TdwUpdaterException(String message) {
        super(message);
    }

    public TdwUpdaterException(Exception e) {
        super(e);
    }

    public TdwUpdaterException(String message, Throwable cause) {
        super(message, cause);
    }
}