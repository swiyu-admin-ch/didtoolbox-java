package ch.admin.bj.swiyu.didtoolbox.context;

import java.io.Serial;

/**
 * The class {@code DidLogCreatorStrategyException} is a <em>checked exception</em> class indicating conditions related to
 * a {@code DidLogCreatorStrategy} implementation class, that any reasonable application might want to catch.
 *
 * @see DidLogCreatorStrategy
 */
public class DidLogCreatorStrategyException extends Exception {

    @Serial
    private static final long serialVersionUID = 9096550421260708236L;

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