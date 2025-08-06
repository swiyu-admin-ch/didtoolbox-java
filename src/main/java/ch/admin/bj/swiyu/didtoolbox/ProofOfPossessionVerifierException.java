package ch.admin.bj.swiyu.didtoolbox;

import lombok.Getter;

/**
 * The class {@code ProofOfPossessionVerificationException} contains information why a ProofOfPossession is invalid.
 */
@Getter
public class ProofOfPossessionVerifierException extends Exception {
    private final ErrorCause errorCause;

    ProofOfPossessionVerifierException(String message, ErrorCause errorCause) {
        super(message);
        this.errorCause = errorCause;
    }

    ProofOfPossessionVerifierException(Exception e) {
        super(e);
        errorCause = null;
    }

    static ProofOfPossessionVerifierException InvalidNonce(String expected, String got) {
        return new ProofOfPossessionVerifierException(String.format("JWT is for nonce '%s', but got nonce '%s'", got, expected), ErrorCause.InvalidNonce);
    }

    static ProofOfPossessionVerifierException Expired() {
        return new ProofOfPossessionVerifierException("The JWT has expired", ErrorCause.Expired);
    }

    static ProofOfPossessionVerifierException UnsupportedAlgorithm(String expected, String got) {
        return new ProofOfPossessionVerifierException(String.format("The JWT uses an unsupported signing algorithm, expected '%s' but got '%s' instead.", expected, got), ErrorCause.UnsupportedAlgorithm);
    }

    static ProofOfPossessionVerifierException KeyNotFound(String key) {
        return new ProofOfPossessionVerifierException(String.format("Key '%s' not found in DID log.", key), ErrorCause.KeyNotFoundInDID);
    }

    static ProofOfPossessionVerifierException InvalidSignature() {
        return new ProofOfPossessionVerifierException("Signature of JWT is invalid", ErrorCause.InvalidSignature);
    }

    public enum ErrorCause {
        UnsupportedAlgorithm,
        InvalidNonce,
        Expired,
        KeyNotFoundInDID,
        InvalidSignature,
    }
}
