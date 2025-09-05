package ch.admin.bj.swiyu.didtoolbox.model;

/**
 * The class {@link MalformedWebVerifiableHistoryDidLogMetaPeekerException} is a <em>checked exception</em> class indicating that a DID log
 * supplied to {@link WebVerifiableHistoryDidLogMetaPeeker#peek(String)} method is undoubtedly anything but a regular
 * {@link DidMethodEnum#WEBVH_1_0}-conform DID log.
 *
 * @see WebVerifiableHistoryDidLogMetaPeeker
 */
public class MalformedWebVerifiableHistoryDidLogMetaPeekerException extends DidLogMetaPeekerException {
    public MalformedWebVerifiableHistoryDidLogMetaPeekerException(String message) {
        super(message);
    }

    public MalformedWebVerifiableHistoryDidLogMetaPeekerException(Exception e) {
        super(e);
    }

    public MalformedWebVerifiableHistoryDidLogMetaPeekerException(String message, Throwable cause) {
        super(message, cause);
    }
}