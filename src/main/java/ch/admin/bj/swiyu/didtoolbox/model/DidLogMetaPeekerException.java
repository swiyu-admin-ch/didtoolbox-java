package ch.admin.bj.swiyu.didtoolbox.model;

/**
 * The class {@link DidLogMetaPeekerException} is a <em>checked exception</em> class indicating conditions related to
 * any of {@link TdwDidLogMetaPeeker} or {@link WebVhDidLogMetaPeeker} helpers that any reasonable application might want to catch.
 *
 * @see TdwDidLogMetaPeeker
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