package ch.admin.bj.swiyu.didtoolbox.context;

import java.io.Serial;

/**
 * The class {@code DidLogUpdaterStrategyException} is a <em>checked exception</em> class indicating conditions related to
 * a {@code DidLogUpdaterStrategy} implementation class, that any reasonable application might want to catch.
 *
 * @see DidLogUpdaterStrategy
 */
public class DidLogUpdaterStrategyException extends Exception {

    @Serial
    private static final long serialVersionUID = -1664747018645375593L;

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