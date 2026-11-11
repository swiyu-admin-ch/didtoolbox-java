package ch.admin.bj.swiyu.didtoolbox.cli;

/**
 * Signals that a CLI command could not be run, carrying a message suitable for being printed to the user as is.
 */
@SuppressWarnings("PMD.MissingSerialVersionUID")
public class CommandException extends Exception {
    public CommandException(String message, Throwable cause) {
        super(message, cause);
    }

    public CommandException(String message) {
        super(message);
    }
}
