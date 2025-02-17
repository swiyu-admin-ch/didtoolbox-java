package ch.admin.bj.swiyu.didtoolbox;

/**
 * The class {@code DidLogMetaPeekerException} is a <em>checked exception</em> class indicating conditions related to
 * {@code DidLogMetaPeeker} class that any reasonable application might want to catch.
 *
 * @see DidLogMetaPeeker
 */
public class DidLogMetaPeekerException extends Exception {
    public DidLogMetaPeekerException(String message) {
        super(message);
    }

    public DidLogMetaPeekerException(Exception e) {
        super(e);
    }

    public DidLogMetaPeekerException(String message, Throwable cause) {
        super(message, cause);
    }
}