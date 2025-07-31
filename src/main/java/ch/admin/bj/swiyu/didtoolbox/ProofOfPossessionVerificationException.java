package ch.admin.bj.swiyu.didtoolbox;

import lombok.Getter;

/**
 * The class {@code ProofOfPossessionVerificationException} contains information why a ProofOfPossession is invalid.
 */
@Getter
public class ProofOfPossessionVerificationException extends Exception {
    private final ErrorCause errorCause;

    public ProofOfPossessionVerificationException(String message, ErrorCause errorCause) {
        super(message);
        this.errorCause = errorCause;
    }

    public static ProofOfPossessionVerificationException InvalidNonce(String expected, String got) {
        return new ProofOfPossessionVerificationException("Expected nonce " + expected + " but got " + got + " instead.", ErrorCause.InvalidNonce);
    }

    public static ProofOfPossessionVerificationException Expired() {
        return new ProofOfPossessionVerificationException("The JWT is expired", ErrorCause.Expired);
    }

    public static ProofOfPossessionVerificationException UnsupportedAlgorithm(String expected, String got) {
        return new ProofOfPossessionVerificationException("The JWT uses an unsupported signing algorithm. Expected " + expected + " but got " + got + " instead.", ErrorCause.UnsupportedAlgorithm);
    }

    public static ProofOfPossessionVerificationException KeyNotFound(String key) {
        return new ProofOfPossessionVerificationException("Key " + key + " not found in DID log.", ErrorCause.KeyNotFoundInDID);
    }

    public static ProofOfPossessionVerificationException InvalidSignature() {
        return new ProofOfPossessionVerificationException("Signature of JWT is invalid", ErrorCause.InvalidSignature);
    }

    public enum ErrorCause {
        UnsupportedAlgorithm,
        InvalidNonce,
        Expired,
        KeyNotFoundInDID,
        InvalidSignature,
    }
}
