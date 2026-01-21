package ch.admin.bj.swiyu.didtoolbox.context;

/**
 * The class {@code NextKeyHashSourceException} is a <em>checked exception</em> class indicating conditions related to
 * any {@code NextKeyHashSource} interface implementation, that any reasonable application might want to catch.
 *
 * @see NextKeyHashSource
 */
public class NextKeyHashSourceException extends Exception {
    public NextKeyHashSourceException(String message) {
        super(message);
    }

    public NextKeyHashSourceException(Exception e) {
        super(e);
    }

    public NextKeyHashSourceException(String message, Throwable cause) {
        super(message, cause);
    }
}