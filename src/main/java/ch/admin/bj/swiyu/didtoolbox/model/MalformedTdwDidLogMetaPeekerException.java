package ch.admin.bj.swiyu.didtoolbox.model;

import java.io.Serial;

/**
 * The class {@link MalformedTdwDidLogMetaPeekerException} is a <em>checked exception</em> class indicating that a DID log
 * supplied to {@link TdwDidLogMetaPeeker#peek(String)} method is undoubtedly anything but a regular
 * {@link DidMethodEnum#TDW_0_3}-conform DID log.
 *
 * @see TdwDidLogMetaPeeker
 */
public class MalformedTdwDidLogMetaPeekerException extends DidLogMetaPeekerException {

    @Serial
    private static final long serialVersionUID = 5610419074218057669L;

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