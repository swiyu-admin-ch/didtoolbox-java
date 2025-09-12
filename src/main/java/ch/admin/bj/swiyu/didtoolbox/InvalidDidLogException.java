package ch.admin.bj.swiyu.didtoolbox;

import java.io.Serial;
import java.security.PrivilegedActionException;

/**
 * Thrown to indicate that a newly created, updated or deactivated DID log is actually not really "resolvable",
 * as it should be.
 */
public class InvalidDidLogException extends RuntimeException {
    /**
     * Constructs an {@code InvalidDidLogException} with no detail message.
     */
    public InvalidDidLogException() {
        super();
    }

    /**
     * Constructs an {@code InvalidDidLogException} with the specified detail message.
     *
     * @param s the detail message.
     */
    public InvalidDidLogException(String s) {
        super(s);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     *
     * <p>Note that the detail message associated with {@code cause} is
     * <i>not</i> automatically incorporated in this exception's detail
     * message.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link Throwable#getMessage()} method).
     * @param cause   the cause (which is saved for later retrieval by the
     *                {@link Throwable#getCause()} method).  (A {@code null} value
     *                is permitted, and indicates that the cause is nonexistent or
     *                unknown.)
     */
    public InvalidDidLogException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new exception with the specified cause and a detail
     * message of {@code (cause==null ? null : cause.toString())} (which
     * typically contains the class and detail message of {@code cause}).
     * This constructor is useful for exceptions that are little more than
     * wrappers for other throwables (for example, {@link
     * PrivilegedActionException}).
     *
     * @param cause the cause (which is saved for later retrieval by the
     *              {@link Throwable#getCause()} method).  (A {@code null} value is
     *              permitted, and indicates that the cause is nonexistent or
     *              unknown.)
     */
    public InvalidDidLogException(Throwable cause) {
        super(cause);
    }

    @Serial
    private static final long serialVersionUID = -4050468765570503214L;
}
