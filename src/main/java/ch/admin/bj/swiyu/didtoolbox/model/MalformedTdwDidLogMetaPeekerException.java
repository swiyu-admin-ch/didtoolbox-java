package ch.admin.bj.swiyu.didtoolbox.model;

/**
 * The class {@link MalformedTdwDidLogMetaPeekerException} is a <em>checked exception</em> class indicating that a DID log
 * supplied to {@link TdwDidLogMetaPeeker#peek(String)} method is undoubtedly anything but a regular
 * {@link DidMethodEnum#TDW_0_3}-conform DID log.
 *
 * @see TdwDidLogMetaPeeker
 */
public class MalformedTdwDidLogMetaPeekerException extends DidLogMetaPeekerException {
    public MalformedTdwDidLogMetaPeekerException(String message) {
        super(message);
    }

    public MalformedTdwDidLogMetaPeekerException(Exception e) {
        super(e);
    }

    public MalformedTdwDidLogMetaPeekerException(String message, Throwable cause) {
        super(message, cause);
    }
}