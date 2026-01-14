package ch.admin.bj.swiyu.didtoolbox;

import java.time.ZonedDateTime;
import java.util.Set;

/**
 * The interface describes a provider of public keys used as publicKeyMultibase property of the verification method.
 * <p>
 * Such key is expected be a public key encoded according to [MULTICODEC] and formatted according to [MULTIBASE].
 * <p>
 * It also describes a signing of hash verification proof.
 */
public interface VerificationMethodKeyProvider {

    String DATA_INTEGRITY_PROOF = "DataIntegrityProof";
    String EDDSA_JCS_2022 = "eddsa-jcs-2022";
    String DID_KEY = "did:key:";
    String PROOF_PURPOSE_AUTHENTICATION = "authentication";
    String PROOF_PURPOSE_ASSERTION_METHOD = "assertionMethod";

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

    /**
     * Create a data integrity proof given an unsecured data document,
     * as specified by <a href="https://www.w3.org/TR/vc-di-eddsa/#create-proof-eddsa-jcs-2022">Data Integrity EdDSA Cryptosuites v1.0</a>.
     * <p>
     * See <a href="https://www.w3.org/TR/vc-di-eddsa/#representation-eddsa-jcs-2022">example</a>
     * <p>
     * The {@code proofValue} property of the {@code proof} MUST be a detached EdDSA signature produced according to
     * <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC8032</a>,
     * encoded using the base-58-btc header and alphabet as described in the
     * <a href="https://www.w3.org/TR/controller-document/#multibase-0">Multibase</a> section of
     * <a href="https://www.w3.org/TR/controller-document/">Controlled Identifier Document</a>.
     *
     * @param unsecuredDocument to create a proof for
     * @param challenge         self-explanatory
     * @param proofPurpose      typically "assertionMethod" or "authentication"
     * @param dateTime          of the proof creation (in <a href="https://www.rfc-editor.org/rfc/rfc3339.html">RFC3339</a> format)
     * @return String representing a "secured" document i.e. the supplied {@code unsecuredDocument} featuring a data integrity proof
     * @throws VerificationMethodKeyProviderException if operation fails for any reason
     */
    String addEddsaJcs2022DataIntegrityProof(String unsecuredDocument,
                                             String challenge,
                                             String proofPurpose,
                                             ZonedDateTime dateTime) throws VerificationMethodKeyProviderException;
}
