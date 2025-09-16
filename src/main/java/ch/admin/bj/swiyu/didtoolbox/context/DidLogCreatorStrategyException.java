package ch.admin.bj.swiyu.didtoolbox.context;

/**
 * The class {@code DidLogCreatorStrategyException} is a <em>checked exception</em> class indicating conditions related to
 * a {@code DidLogCreatorStrategy} implementation class, that any reasonable application might want to catch.
 *
 * @see DidLogCreatorStrategy
 */
public class DidLogCreatorStrategyException extends Exception {
    public DidLogCreatorStrategyException(String message) {
        super(message);
    }

    public DidLogCreatorStrategyException(Exception e) {
        super(e);
    }

    public DidLogCreatorStrategyException(String message, Throwable cause) {
        super(message, cause);
    }
}