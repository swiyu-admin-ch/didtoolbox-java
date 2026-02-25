package ch.admin.bj.swiyu.didtoolbox;

import lombok.Getter;

import java.io.Serial;

/**
 * The class {@code ProofOfPossessionVerificationException} contains information why a ProofOfPossession is invalid.
 */
@Getter
public class ProofOfPossessionVerifierException extends Exception {

    @Serial
    private static final long serialVersionUID = -3214408602387693957L;

    private final ErrorCause errorCause;

    ProofOfPossessionVerifierException(String message, ErrorCause errorCause) {
        super(message);
        this.errorCause = errorCause;
    }

    ProofOfPossessionVerifierException(Exception e) {
        super(e);
        errorCause = null;
    }

    static ProofOfPossessionVerifierException invalidNonce(String expected, String got) {
        return new ProofOfPossessionVerifierException(String.format("JWT is for nonce '%s', but got nonce '%s'", got, expected), ErrorCause.INVALID_NONCE);
    }

    static ProofOfPossessionVerifierException unparsable(Exception cause) {
        return new ProofOfPossessionVerifierException(String.format("The JWT cannot be parsed due to: %s", cause.getLocalizedMessage()), ErrorCause.UNPARSABLE);
    }

    static ProofOfPossessionVerifierException malformedClaimKid(Exception cause) {
        return new ProofOfPossessionVerifierException(String.format("The JWT claim 'kid' features no multibase-encoded Ed25519 public key: %s", cause.getLocalizedMessage()), ErrorCause.MALFORMED_CLAIM_KID);
    }

    static ProofOfPossessionVerifierException expired() {
        return new ProofOfPossessionVerifierException("The JWT has expired", ErrorCause.EXPIRED);
    }

    static ProofOfPossessionVerifierException unsupportedAlgorithm(String expected, String got) {
        return new ProofOfPossessionVerifierException(String.format("The JWT uses an unsupported signing algorithm, expected '%s' but got '%s' instead.", expected, got), ErrorCause.UNSUPPORTED_ALGORITHM);
    }

    static ProofOfPossessionVerifierException keyMismatch(String key) {
        return new ProofOfPossessionVerifierException(String.format("Key '%s' not found in DID log.", key), ErrorCause.KEY_MISMATCH);
    }

    static ProofOfPossessionVerifierException invalidSignature() {
        return new ProofOfPossessionVerifierException("Signature of JWT is invalid", ErrorCause.INVALID_SIGNATURE);
    }

    static ProofOfPossessionVerifierException unsupportedKeySubtype() {
        return new ProofOfPossessionVerifierException("The key subtype is not supported", ErrorCause.UNSUPPORTED_KEY_SUBTYPE);
    }

    static ProofOfPossessionVerifierException failedToVerify(Exception cause) {
        return new ProofOfPossessionVerifierException(String.format("Failed to verify JWT due to: %s", cause.getLocalizedMessage()), ErrorCause.FAILED_TO_VERIFY);
    }

    public enum ErrorCause {
        UNSUPPORTED_ALGORITHM,
        INVALID_NONCE,
        UNPARSABLE,
        MALFORMED_CLAIM_KID,
        EXPIRED,
        KEY_MISMATCH,
        INVALID_SIGNATURE,
        UNSUPPORTED_KEY_SUBTYPE,
        FAILED_TO_VERIFY
    }
}
