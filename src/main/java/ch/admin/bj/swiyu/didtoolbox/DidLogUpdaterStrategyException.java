package ch.admin.bj.swiyu.didtoolbox;

/**
 * The class {@code DidLogUpdaterStrategyException} is a <em>checked exception</em> class indicating conditions related to
 * {@code DidLogUpdaterStrategy} class that any reasonable application might want to catch.
 *
 * @see DidLogUpdaterStrategy
 */
public class DidLogUpdaterStrategyException extends Exception {
    public DidLogUpdaterStrategyException(String message) {
        super(message);
    }

    public DidLogUpdaterStrategyException(Exception e) {
        super(e);
    }

    public DidLogUpdaterStrategyException(String message, Throwable cause) {
        super(message, cause);
    }
}