package ch.admin.bj.swiyu.didtoolbox;

import java.io.Serial;

/**
 * The class {@link ProofOfPossessionCreatorException} is a <em>checked exception</em> class indicating conditions related to
 * {@link ProofOfPossessionCreator} class that any reasonable application might want to catch.
 *
 * @see ProofOfPossessionCreator
 */
public class ProofOfPossessionCreatorException extends Exception {

    @Serial
    private static final long serialVersionUID = -8688911417489177064L;

    public ProofOfPossessionCreatorException(String message) {
        super(message);
    }

    public ProofOfPossessionCreatorException(Exception e) {
        super(e);
    }
}
