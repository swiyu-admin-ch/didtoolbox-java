package ch.admin.bj.swiyu.didtoolbox.cli;

/**
 * Signals that a CLI command could not be run, carrying a message suitable for being printed to the user as is.
 */
@SuppressWarnings("PMD.MissingSerialVersionUID")
public class CommandException extends Exception {
    CommandException(String message, Throwable cause) {
        super(message, cause);
    }

    CommandException(String message) {
        super(message);
    }
}
