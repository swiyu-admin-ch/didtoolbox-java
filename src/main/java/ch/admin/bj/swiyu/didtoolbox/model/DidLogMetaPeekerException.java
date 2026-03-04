package ch.admin.bj.swiyu.didtoolbox.model;

import java.io.Serial;

/**
 * The class {@link DidLogMetaPeekerException} is a <em>checked exception</em> class indicating conditions related to
 * any of {@link TdwDidLogMetaPeeker} or {@link WebVerifiableHistoryDidLogMetaPeeker} helpers that any reasonable application might want to catch.
 *
 * @see TdwDidLogMetaPeeker
 */
public class DidLogMetaPeekerException extends Exception {

    @Serial
    private static final long serialVersionUID = 4566693281437485108L;

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