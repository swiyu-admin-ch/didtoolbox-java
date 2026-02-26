package ch.admin.bj.swiyu.didtoolbox;

import java.io.Serial;

/**
 * The class {@link TdwUpdaterException} is a <em>checked exception</em> class indicating conditions related to
 * {@link TdwUpdater} class that any reasonable application might want to catch.
 *
 * @see TdwUpdater
 */
public class TdwUpdaterException extends Exception {

    @Serial
    private static final long serialVersionUID = 8078516358977701720L;

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