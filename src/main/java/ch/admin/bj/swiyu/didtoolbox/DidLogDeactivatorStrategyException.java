package ch.admin.bj.swiyu.didtoolbox;

/**
 * The class {@code DidLogDeactivatorStrategyException} is a <em>checked exception</em> class indicating conditions related to
 * {@code DidLogDeactivatorStrategy} class that any reasonable application might want to catch.
 *
 * @see DidLogDeactivatorStrategy
 */
public class DidLogDeactivatorStrategyException extends Exception {
    public DidLogDeactivatorStrategyException(String message) {
        super(message);
    }

    public DidLogDeactivatorStrategyException(Exception e) {
        super(e);
    }

    public DidLogDeactivatorStrategyException(String message, Throwable cause) {
        super(message, cause);
    }
}