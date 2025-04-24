package ch.admin.bj.swiyu.didtoolbox;

import java.util.Set;

/**
 * The interface describes a provider of public keys used as publicKeyMultibase property of the verification method.
 * <p>
 * Such key is expected be a public key encoded according to [MULTICODEC] and formatted according to [MULTIBASE].
 * <p>
 * It also describes a signing of hash verification proof.
 */
public interface VerificationMethodKeyProvider {
    /**
     * Delivers the publicKeyMultibase property of the verification method, that  MUST be a public key encoded according to
     * [MULTICODEC] and formatted according to [MULTIBASE].
     * <p>
     * For instance, the multicodec encoding of an Ed25519 public key is the two-byte prefix 0xed01 followed by the 32-byte public key data.
     *
     * @return a public verification key in multibase format.
     */
    String getVerificationKeyMultibase();

    /**
     * Generate a signature for the (hashed) verification proof.
     *
     * @param message to sign
     * @return signed message
     */
    byte[] generateSignature(byte[] message);

    /**
     * Checks if the public verification key (in multibase format) is part of the supplied set of keys.
     *
     * @param multibaseEncodedKeys
     * @return
     */
    boolean isKeyMultibaseInSet(Set<String> multibaseEncodedKeys);
}
