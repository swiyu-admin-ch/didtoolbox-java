package ch.admin.bj.swiyu.didtoolbox.context;

import java.io.Serial;

/**
 * Thrown to indicate that a method in charge of "building" a DID log entry has not yet been passed all required arguments.
 *
 * @since 1.9.0
 */
public class IncompleteDidLogEntryBuilderException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 2890032589302021857L;

    /**
     * Constructs an {@code IncompleteDidLogEntryBuilderException} with no detail message.
     */
    public IncompleteDidLogEntryBuilderException() {
        super();
    }

    /**
     * Constructs an {@code IncompleteDidLogEntryBuilderException} with the specified detail message.
     *
     * @param s the detail message.
     */
    public IncompleteDidLogEntryBuilderException(String s) {
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
    public IncompleteDidLogEntryBuilderException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new exception with the specified cause and a detail
     * message of {@code (cause==null ? null : cause.toString())} (which
     * typically contains the class and detail message of {@code cause}).
     * This constructor is useful for exceptions that are little more than
     * wrappers for other throwables.
     *
     * @param cause the cause (which is saved for later retrieval by the
     *              {@link Throwable#getCause()} method).  (A {@code null} value is
     *              permitted, and indicates that the cause is nonexistent or
     *              unknown.)
     */
    public IncompleteDidLogEntryBuilderException(Throwable cause) {
        super(cause);
    }
}
