package ch.admin.bj.swiyu.didtoolbox;

/**
 * The class {@link ProofOfPossessionCreatorException} is a <em>checked exception</em> class indicating conditions related to
 * {@link ProofOfPossessionCreator} class that any reasonable application might want to catch.
 *
 * @see ProofOfPossessionCreator
 */
public class ProofOfPossessionCreatorException extends Exception {
    public ProofOfPossessionCreatorException(Exception e) {
        super(e);
    }
}
